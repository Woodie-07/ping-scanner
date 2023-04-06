from flask import Flask, jsonify, request, render_template, redirect, send_file
import subnet_tools
import mysql.connector
import socket
import threading
import os
import time

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
        host="127.0.0.1",
        user="pingscanner",
        password="7OBZH%!lLXa*P*zV",
        database="pingscanner"
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

cursor.execute("SELECT * FROM scans WHERE state = 0")
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

def worker():
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

            os.mkdir("jobs/" + str(job.id))

            subnet = subnet_tools.Subnet(job.ip, job.cidr)

            with open("masscan.conf", "r") as f:
                masscanConfTemplate = f.read()

            masscanConf = masscanConfTemplate.replace("RANGE", str(subnet))

            with open("jobs/" + str(job.id) + "/masscan.conf", "w") as f:
                f.write(masscanConf)

            os.system("cd jobs/" + str(job.id) + " && masscan -c masscan.conf")
            
            job.state = States.RENDERING
            db, cursor = openSQLConn()
            cursor.execute("UPDATE scans SET state = %s WHERE id = %s", (job.state, job.id))
            db.commit()
            closeSQLConn(db, cursor)

            renderCIDR = job.cidr
            if renderCIDR % 2 == 1:
                renderCIDR -= 1

            os.system(f"/bin/bash -c 'ipv4-heatmap/ipv4-heatmap -y {job.ip}/{str(renderCIDR)} -o jobs/{str(job.id)}/image.png -z 0 < jobs/{str(job.id)}/results.txt'")

            job.state = States.DONE
            db, cursor = openSQLConn()
            cursor.execute("UPDATE scans SET state = %s WHERE id = %s", (job.state, job.id))
            db.commit()
            closeSQLConn(db, cursor)

threading.Thread(target=worker).start()


app = Flask(__name__)

@app.route('/', methods = ['GET'])
def index():
    return render_template("index.html", recentscans = ["127.0.0.0/8"])

@app.route("/startscan", methods = ['POST'])
def startscan():
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

    return redirect("/scan/" + str(id))

@app.route("/scan/<id>", methods = ['GET'])
def scan(id):
    db, cursor = openSQLConn()
    cursor.execute("SELECT ip, cidr, client_ip, state, timestamp FROM scans WHERE id = %s", (id,))
    scan = cursor.fetchone()
    closeSQLConn(db, cursor)

    if scan is None:
        return "<img src=\"https://http.cat/404\">", 404

    scanIP = socket.inet_ntoa(scan[0])
    scanCIDR = scan[1]
    scanClientIP = socket.inet_ntoa(scan[2])
    scanState = scan[3]
    ts = scan[4]
    subnet = scanIP + "/" + str(scanCIDR)

    if scanState == States.PENDING:
        stateString = "PENDING"
        resultsList = None
        imageURL = None
    elif scanState == States.SCANNING:
        stateString = "SCANNING"
        resultsList = None
        imageURL = None
    elif scanState == States.RENDERING:
        stateString = "RENDERING"
        with open("/scans/" + str(id) + "/results.txt", "r") as f:
            resultsList = [line.strip() for line in f.readlines()]
        imageURL = None
    elif scanState == States.DONE:
        stateString = "DONE"
        with open("/scans/" + str(id) + "/results.txt", "r") as f:
            resultsList = [line.strip() for line in f.readlines()]
        imageURL = "/scan/" + str(id) + "/image.png"

    return render_template("scan.html", id = str(id), subnet = subnet, state = stateString, results = resultsList, image = imageURL, datetime = ts.strftime("%Y-%m-%d %H:%M:%S"))

@app.route("/scan/<id>/image.png", methods = ['GET'])
def scanimage(id):
    return send_file("/scans/" + str(id) + "/image.png")
  
if __name__ == '__main__':
    app.run(debug = True, host="0.0.0.0")