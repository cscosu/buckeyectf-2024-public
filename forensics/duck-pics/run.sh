

tshark -r $1 -T fields -e usbhid.data | grep -E "." | grep -v '0000000000000000' > capdata.txt
python3 PUK.py capdata.txt
