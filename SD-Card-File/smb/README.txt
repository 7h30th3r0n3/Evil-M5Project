SMB Explorer - SD files  (this folder is  evil/smb/  on the card)
=================================================================

Edit these on your computer, then put them back on the SD card.

  smb_creds.txt    user:password pairs, one per line  (PAIRS spray mode)
  smb_hashes.txt   NT hashes for pass-the-hash (user:nthash or pwdump line)
  hosts.txt        extra target IPs to add to discovery, one per line (optional)

COMBO spray (users x passwords), instead of pairs:
  Create BOTH of these (then pairs mode is ignored):
    smb_users.txt  one username per line
    smb_pass.txt   one password per line
  Tip: the serial command  smb_seed  writes a ready-made common list for you.

Written BY the device (you do not create these):
  spider_<share>.txt   recursive file tree from a spider
  loot_<share>.txt     secret-looking files found (+ peeked lines)
  report_<ip>.txt      recon + per-share read/write access matrix
  smb_hits.txt         successful spray results
  mirror/<share>/...   files pulled by a mirror
  session.log          timestamped log

Use only on networks and hosts you own or are authorized to assess.
