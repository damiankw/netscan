# Get the IP Address
printf "*** Found IP Address: "
IP_ADDR=$(ifconfig | grep inet| awk '($1 == "inet") && ($2 != "127.0.0.1") { print $2 }')
echo $IP_ADDR

# Get the IP Range
RANGE="${IP_ADDR%%.*}"
IP_ADDR=${IP_ADDR#*.*}
RANGE="$RANGE.${IP_ADDR%%.*}"
IP_ADDR=${IP_ADDR#*.*}
RANGE="$RANGE.${IP_ADDR%%.*}"
IP_ADDR=${IP_ADDR#*.*}
RANGE="$RANGE.0"

printf "*** Scanning network: $RANGE/24"
# Print out friendly
nmap -sPn $RANGE/24 | awk '($1 == "MAC") {printf "[ "$3" "$4" "$5" "$6" "$7"]"} ($1 == "Host") {printf " "$4" "$5} ($1 == "Nmap" && $2 == "scan") {print ""; printf "- "$5" "$6} ($1 == "Nmap") && ($2 == "done:") {printf "\n*** Scan Complete\n"}'
