import pprint

messageType = 255
BR_VERSION = "00.00.01-alpha"
altAddress = "000.000.000.000:65535"
toClient = "21c29bbb-0e2b-4180-a0b6-70a8a669c4cc"
fromClient = "6d48ed70-82d0-481a-876b-6a609c119234"
publicKey = """-----BEGIN RSA PUBLIC KEY-----
MIICCgKCAgEAg7ySCVZJTSG75QFcwLHmqtt/46jLjvc6RHZAweEAV1nqtqKThSj8
SjvOo2BYK3mJvTENRj1zMxmE2cvgLc54CN+PBA1y6TmwZRfg49pKJ4Ukc28o3T1x
GW5YY+Boc1nQqhTIefBwtDLMe4QuckOjuwwAh1GDPAq4VEWox+DJN6f9MMsaGwg/
lrPYrPNeEFtZJbIEEps3+k0VtlVM9NXxBxyrG0JFtta58ADK2Qh7bK/KyMKVSdDH
QCaoZ0drDdsJ06OMRXZROWN2zDteTqCJNii+lS3h+q9fmC09xlOrB/G9eKlEs4wS
4RnSqGhrGAqCBhzFdsfvXEtxO+9SX3m5ZrbwzZpnf+lQnyl+7rDiGpQqkQ/Clj+3
/Kc94e1Qn3mTDFsGgTKotjnLRxxVUOSMwPMU5mT0BEmw9qOPxQhIqzz5wbX8RBwq
ROshVgJiHnTH7lE1fmnk/CzqQGfrx0caLLZb3LyxxW3YNREeWp3+ooiwMEmszbfn
xIewbxTCQrHQX54duNLaWIcvNs7AFcYcZ6R3Gi2thKB+NGXSSeXMy/mK9C7vnp8g
xaBpJLEYyhgzNpcN0TbjIrQcJ3vpX3Ow8X3cEYWVjwcQ1VG3UImxbinCKvjxJivQ
FJSn8C/RPguo//mWjF0xIbD9HyjfRQDqlUzSSFRVTObeH0V71jmXCz8CAwEAAQ==
-----END RSA PUBLIC KEY-----"""

msgtype = bytes(messageType.to_bytes(1, byteorder='little'))
version = bytes(BR_VERSION.encode("utf-8"))
altIP = bytes(altAddress.encode("utf-8"))
pubReturn = bytes(publicKey.encode("utf-8"))

packet = msgtype + version + altIP + pubReturn
print("Full packet: ")
print(f"Length: {len(packet)}")
print(pprint.pformat(packet.hex(" ", 1)))
print(f"Max length of messagetype: {len(msgtype)}")
print(f"Max length of version: {len(version)}")
print(f"Max length of return address: {len(altAddress)}")
print(f"Max length of toclient: {len(altAddress)}")
print(f"Max length of fromclient: {len(altAddress)}")
print(f"Max length of pubkey: {len(altAddress)}")


