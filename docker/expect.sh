#!/usr/bin/expect -f

set password [lindex $argv 0];

spawn warpgate hash
expect "*Password to be hashed*"
send -- "$password\r"
expect eof
