read -p 'Enter the directory path: ' directory

for file in "$directory"/*; do
  for nfcapd in "$file"/2020/05/01/*; do
    #echo ""
    #echo "$nfcapd"
    dir_path=${file%.*}
    filename=${nfcapd##*/}
    #echo ""
    #echo "$filename"
    name="/home/rkgegan/results/netflow_results/"
    name+="$filename"
    name+=".txt"
    #echo ""
    #echo "$name"
    nfdump -r $nfcapd -s proto -o csv > $name
  done
  echo "$file"
  cat *.txt > nfdump_proto.txt
  rm nfcapd*.txt
  python3 protocol_csv.py nfdump_proto.txt
  rm nfdump_proto.txt
  echo ""
done
