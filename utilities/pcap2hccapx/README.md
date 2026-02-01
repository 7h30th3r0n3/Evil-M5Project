
# pcap2hccapx :

A script that extracts and transforms PCAP to HCCAPX to be able to use it with hashcat.
It is also useful to extract each PMKID or 4-way handshake into a single file.

## prerequisites:
installed:
- tshark
- hcxpcapngtool

## Procedure:

Place the script in a folder,
then place all the PCAP files you want to transform,
run the script and folders with all data are created.

Note:
You can merge all the HCCAPX files into one file for parallel cracking with:

```cat *.hccapx > all.hccapx```
