class IP:
    def validateIP(self, ip: str) -> bool:
        ipSplit = ip.split('.')
        if len(ipSplit) != 4:
            return False
        for octet in ipSplit:
            if not octet.isdigit():
                return False
            if int(octet) > 255 or int(octet) < 0:
                return False
        return True

    def toBits(self):
        ipSplit = self.ip.split('.')
        binStr = ""
        for octet in ipSplit:
            octet = int(octet)
            binStr += format(octet,'08b')

        binary = int(binStr, 2)
        return Bits(binary)

    def __init__(self, ip):
        if not isinstance(ip, str):
            raise TypeError("IP must be a string")

        if not self.validateIP(ip):
            raise ValueError("Invalid IP")
        
        self.ip = ip
    
    def __eq__(self, other):
        if isinstance(other, IP):
            return self.ip == other.ip

        return self.ip == other

    def __ne__(self, other):
        return not self.__eq__(other)

    def __le__(self, other):
        bits = self.IPToBits(self.ip)
        otherBits = self.IPToBits(other.ip)
        for i in range(bits):
            if bits[i] and not otherBits[i]:
                return False
            elif not bits[i] and otherBits[i]:
                return True
        return True

    def __lt__(self, other):
        bits = self.IPToBits(self.ip)
        otherBits = self.IPToBits(other.ip)
        for i in range(bits):
            if bits[i] and not otherBits[i]:
                return False
            elif not bits[i] and otherBits[i]:
                return True
        return False

    def __gt__(self, other):
        bits = self.IPToBits(self.ip)
        otherBits = self.IPToBits(other.ip)
        for i in range(bits):
            if bits[i] and not otherBits[i]:
                return True
            elif not bits[i] and otherBits[i]:
                return False
        return False

    def __ge__(self, other):
        bits = self.IPToBits(self.ip)
        otherBits = self.IPToBits(other.ip)
        for i in range(bits):
            if bits[i] and not otherBits[i]:
                return True
            elif not bits[i] and otherBits[i]:
                return False
        return True

    def __bytes__(self):
        return bytes(self.ip, "utf-8")

    def __str__(self):
        return self.ip

    def __repr__(self):
        return self.ip

class Bits:
    def toIP(self):
        binToIP = ""
        for i in range(0, len(self), 8):
            count = 7
            binStr = 0
            chunk = self[i:i+8]
            for bit in chunk:
                binStr += 2 ** count if bit else 0
                count -= 1
            binToIP += str(binStr) + "."
        return IP(binToIP[:-1])

    def __init__(self, bits: int, size: int = 32):
        if not isinstance(bits, int):
            raise TypeError("Bits must be a int")

        self.bits = bits
        self.size = size

    def HRBits(self):
        bitsStr = ""
        for bit in iter(self):
            bitsStr += "1" if bit else "0"
        return bitsStr

    def __eq__(self, other):
        return self.bits == other.bits and self.size == other.size

    def __str__(self):
        return self.HRBits()

    def __repr__(self):
        return self.HRBits()

    def __getitem__(self, key):
        if isinstance(key, slice):
            start = key.start
            stop = key.stop
            step = key.step
            if start is None:
                start = 0
            if stop is None:
                stop = self.size
            if step is None:
                step = 1
            if start < 0:
                start = self.size + start
            if stop < 0:
                stop = self.size + stop
            bits = ""
            for i in range(start, stop, step):
                bits += str(self.__getitem__(self.size - 1 - i))

            for _ in range((stop - start) // step - len(bits)):
                bits += "0"
                
            newBits = Bits(int(bits, 2), len(bits))
            return newBits

        return (self.bits >> key) & 1

    def __iter__(self):
        self.index = self.size - 1
        return self

    def __next__(self):
        if self.index >= 0:
            bit = self.__getitem__(self.index)
            self.index -= 1
            return bit
        else:
            raise StopIteration

    def __len__(self):
        return self.size

    def __add__(self, other):
        if isinstance(other, Bits):
            newBitsStr = self.HRBits() + other.HRBits()
            return Bits(int(newBitsStr, 2), len(newBitsStr))

        if isinstance(other, int):
            return Bits(self.bits + other, self.size)

    def __and__(self, other):
        if isinstance(other, Bits):
            return Bits(self.bits & other.bits, self.size)

        return Bits(self.bits & other, self.size)

    def __invert__(self):
        return Bits(~self.bits, self.size)

    def __or__(self, other):
        if isinstance(other, Bits):
            return Bits(self.bits | other.bits, self.size)

        return Bits(self.bits | other, self.size)


class Subnet:
    def numIPs(self):
        return 2 ** (32 - self.CIDR)

    def __init__(self, ip, CIDR):
        self.CIDR = CIDR
        mask = Bits(int("1" * CIDR + "0" * (32 - CIDR), 2), 32)
        self.subnetBits = (IP(ip) if isinstance(ip, str) else ip).toBits() & mask

    def split(self):
        newCIDR = self.CIDR + 1
        subnetABits = self.subnetBits
        subnetBBits = self.subnetBits + (2 ** (32 - newCIDR))
        subnetA = Subnet(subnetABits.toIP(), newCIDR)
        subnetB = Subnet(subnetBBits.toIP(), newCIDR)

        return [subnetA, subnetB]

    def splitToCIDR(self, targetCIDR):
        newSubnets = [self]
        for _ in range(targetCIDR - self.CIDR):
            tempSubnets = []
            for subnet in newSubnets:
                for subnet in subnet.split():
                    tempSubnets.append(subnet)
            newSubnets = tempSubnets

        return newSubnets

    def __str__(self):
        return str(self.subnetBits.toIP()) + "/" + str(self.CIDR)

    def __repr__(self):
        return str(self.subnetBits.toIP()) + "/" + str(self.CIDR)

    def __eq__(self, other):
        return (self.subnetBits == other.subnetBits) and (self.CIDR == other.CIDR)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __iter__(self):
        self.index = 0
        return self

    def __next__(self):
        if self.index < self.numIPs():
            bits = self.subnetBits | self.index
            self.index += 1
            return bits.toIP()
        else:
            raise StopIteration