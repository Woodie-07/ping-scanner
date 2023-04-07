from flask import Flask, jsonify, request, render_template, redirect, send_file
import subnet_tools
import mysql.connector
import socket
import threading
import os
import time
import config

class States:
    PENDING = 0
    SCANNING = 1
    RENDERING = 2
    DONE = 3


class Job:
    def __init__(self, id, ip, cidr, state = States.PENDING):
        self.id = id
        self.ip = ip
        self.cidr = cidr
        self.state = state

inProgressJobs = []

def openSQLConn():
    db = mysql.connector.connect(
        host=config.SQLHost,
        user=config.SQLUser,
        password=config.SQLPassword,
        database=config.SQLDatabase
    )

    return db, db.cursor()

def closeSQLConn(db, cursor):
    cursor.close()
    db.close()

db, cursor = openSQLConn()

cursor.execute("""CREATE TABLE IF NOT EXISTS `scans` (
	`id` INT unsigned NOT NULL AUTO_INCREMENT,
	`ip` BINARY(4) NOT NULL,
	`cidr` TINYINT unsigned NOT NULL,
	`client_ip` BINARY(4) NOT NULL,
    `state` TINYINT unsigned NOT NULL DEFAULT 0,
    `timestamp` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY (`id`)
);""")

# load all scans that are not done
cursor.execute("SELECT * FROM scans WHERE state != 3")
scans = cursor.fetchall()
for scan in scans:
    id = scan[0]
    ip = socket.inet_ntoa(scan[1])
    cidr = scan[2]
    clientIP = socket.inet_ntoa(scan[3])
    state = scan[4]
    timestamp = scan[5]

    job = Job(id, ip, cidr, state)
    inProgressJobs.append(job)

closeSQLConn(db, cursor)

def pingworker():
    while True:
        try:
            job = inProgressJobs.pop(0)
        except IndexError:
            time.sleep(5)
            continue
        
        if job.state == States.PENDING:
            job.state = States.SCANNING
        
            db, cursor = openSQLConn()
            cursor.execute("UPDATE scans SET state = %s WHERE id = %s", (job.state, job.id))
            db.commit()
            closeSQLConn(db, cursor)

        if job.state == States.SCANNING:
            try:
                os.mkdir("jobs/" + str(job.id))
            except FileExistsError:
                # likely interrupted scan, purge results and rescan
                os.remove("jobs/" + str(job.id) + "/results.txt")

            subnet = subnet_tools.Subnet(job.ip, job.cidr)

            rate = config.calcRate(job.cidr)

            with open("masscan.conf", "r") as f:
                masscanConf = f.read()

            masscanConf = masscanConf.replace("RANGE", str(subnet))
            masscanConf = masscanConf.replace("RATE", str(rate))

            with open("jobs/" + str(job.id) + "/masscan.conf", "w") as f:
                f.write(masscanConf)

            os.system("cd jobs/" + str(job.id) + " && masscan -c masscan.conf")

            if not os.path.exists("jobs/" + str(job.id) + "/results.txt"):
                # masscan failed to scan, probably because the range was entirely excluded
                # just write an empty file
                with open("jobs/" + str(job.id) + "/results.txt", "w") as f:
                    f.write("")
            
            job.state = States.RENDERING
            db, cursor = openSQLConn()
            cursor.execute("UPDATE scans SET state = %s WHERE id = %s", (job.state, job.id))
            db.commit()
            closeSQLConn(db, cursor)

        if job.state == States.RENDERING:
            renderCIDR = job.cidr
            if renderCIDR % 2 == 1:
                renderCIDR -= 1

            os.system(f"/bin/bash -c 'ipv4-heatmap/ipv4-heatmap -y {job.ip}/{str(renderCIDR)} -o jobs/{str(job.id)}/image.png -z 0 < jobs/{str(job.id)}/results.txt'")

            job.state = States.DONE
            db, cursor = openSQLConn()
            cursor.execute("UPDATE scans SET state = %s WHERE id = %s", (job.state, job.id))
            db.commit()
            closeSQLConn(db, cursor)

threading.Thread(target=pingworker, daemon=True).start()


app = Flask(__name__)

@app.route('/', methods = ['GET'])
def index():
    db, cursor = openSQLConn()
    cursor.execute("SELECT ip, cidr, timestamp, id FROM scans ORDER BY timestamp DESC LIMIT 10")
    recentscanslist = cursor.fetchall()
    closeSQLConn(db, cursor)

    recentscans = []

    for scan in recentscanslist:
        ip = socket.inet_ntoa(scan[0])
        cidr = scan[1]
        timestamp = scan[2]
        id = scan[3]

        recentscans.append({
            "id": str(id),
            "subnet": ip + "/" + str(cidr),
            "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S")
        })


    return render_template("index.html", recentscans = recentscans, qsize = len(inProgressJobs))

@app.route("/startscan", methods = ['POST'])
def startscan():
    if len(inProgressJobs) > 5:
        return "<p>Queue full (max 5), try later</p><br><img src=\"https://http.cat/503\">", 503

    subnet = request.form.get("subnet")
    clientIP = request.remote_addr
    headers = request.headers

    if "CF-Connecting-IP" in headers:
        clientIP = headers["CF-Connecting-IP"]

    clientIPBytes = socket.inet_aton(clientIP)

    try:
        subnetSplit = subnet.split("/")
        subnetIP = subnetSplit[0]
        subnetCIDR = int(subnetSplit[1])

        subnetIPBytes = socket.inet_aton(subnetIP)
    except:
        return "<img src=\"https://http.cat/400\">", 400
    
    if subnetCIDR < 8 or subnetCIDR > 32:
        return "<img src=\"https://http.cat/400\">", 400

    db, cursor = openSQLConn()
    cursor.execute("INSERT INTO scans (ip, cidr, client_ip) VALUES (%s, %s, %s)", (subnetIPBytes, subnetCIDR, clientIPBytes))
    id = cursor.lastrowid
    db.commit()
    closeSQLConn(db, cursor)

    inProgressJobs.append(Job(id, subnetIP, subnetCIDR, 0))

    return redirect("/scan/" + str(id))

@app.route("/scan/<id>", methods = ['GET'])
def scan(id):
    db, cursor = openSQLConn()
    cursor.execute("SELECT ip, cidr, state, timestamp FROM scans WHERE id = %s", (id,))
    scan = cursor.fetchone()
    closeSQLConn(db, cursor)

    if scan is None:
        return "<img src=\"https://http.cat/404\">", 404

    scanIP = socket.inet_ntoa(scan[0])
    scanCIDR = scan[1]
    scanState = scan[2]
    ts = scan[3]
    subnet = scanIP + "/" + str(scanCIDR)

    stateString = {
        States.PENDING: "Pending",
        States.SCANNING: "Scanning",
        States.RENDERING: "Rendering",
        States.DONE: "Done"
    }.get(scanState)

    resultsList, imageURL = None, None

    if scanState >= States.RENDERING:
        with open(f"jobs/{str(id)}/results.txt", "r") as f:
            resultsList = [line.strip() for line in f.readlines()]

    if scanState == States.DONE:
        imageURL = f"/scan/{str(id)}/image.png"

    rate = config.calcRate(scanCIDR)

    return render_template("scan.html", id = str(id), subnet = subnet, state = stateString, results = resultsList, image = imageURL, datetime = ts.strftime("%Y-%m-%d %H:%M:%S"), rate=str(rate))

@app.route("/scan/<id>/image.png", methods = ['GET'])
def scanimage(id):
    return send_file("jobs/" + str(id) + "/image.png")
  
if __name__ == '__main__':
    app.run(host=config.listenHost, port=config.listenPort)
