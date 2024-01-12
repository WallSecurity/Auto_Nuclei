#!/bin/bash
TARGET=$1
DISCORD_ID=""
DISCORD_TOKEN=""
RECONFTW_DIR="/root/Recon/ReconFTW/${TARGET}"
ROOT_DIR="/root/Recon/Programs/${TARGET}"
WAYBACK_DIR="/root/Recon/Programs/${TARGET}/wayback"
CONTENT_DIR="/root/Recon/Programs/${TARGET}/content"
SUBDOMAINS_DIR="/root/Recon/Programs/${TARGET}/subdomains"
NUCLEI_DIR="/root/Recon/Programs/${TARGET}/nuclei"
NUCLEI_OUTPUT_DIR="/root/Recon/Programs/${TARGET}/nuclei/output"
WORDLIST_DIR="/opt/wordlists/script_payloads"
NUCLEI_TEMPLATES='/root/Custom-Nuclei-Templates/fuzzing'

BLUE=' \033[1;32m'
RESET='\033[0m\n'

RUN_RECONFTW=false

# Check input
if [ "$#" -eq 0 ]; then
        echo "usage: auto_nuclei <domain> [-r]"
	echo "	-r	run reconftw on the target"
        exit
fi
if [ "$1" == "-h" ]; then
        echo "usage: auto_nuclei <domain> [-r]"
	echo "	-r	run reconftw on the target"
        exit
fi
if [ "$2" == "-r" ]; then
	RUN_RECONFTW=true
fi

# Create directory structure
if [ ! -d ${ROOT_DIR} ];then
        mkdir ${ROOT_DIR}
fi
if [ ! -d ${WAYBACK_DIR} ];then
        mkdir ${WAYBACK_DIR}
fi
if [ ! -d ${CONTENT_DIR} ];then
        mkdir ${CONTENT_DIR}
fi
if [ ! -d ${SUBDOMAINS_DIR} ];then
        mkdir ${SUBDOMAINS_DIR}
fi
if [ ! -d ${NUCLEI_DIR} ];then
        mkdir ${NUCLEI_DIR}
fi
if [ ! -d ${NUCLEI_OUTPUT_DIR} ];then
        mkdir ${NUCLEI_OUTPUT_DIR}
fi

# Run reconftw.sh
if [ ${RUN_RECONFTW} = true ]; then
	/bin/bash /opt/reconftw/reconftw.sh -d ${TARGET} -r
fi

# Sort endpoints - create payload files - run nuclei
ENDPOINTS_FILE="${RECONFTW_DIR}/webs/url_extract.txt"
if [ -f "${ENDPOINTS_FILE}" ]; then
	/usr/bin/cat ${ENDPOINTS_FILE} | grep "?" | urldedupe -m "s,qs" > ${WAYBACK_DIR}/params.txt
	/usr/local/bin/pathi_generator "${WAYBACK_DIR}/params.txt" | urldedupe > ${NUCLEI_DIR}/paths.txt
else
	echo ${TARGET} | waybackurls >> ${WAYBACK_DIR}/url_extract.txt
	/usr/bin/python3 /opt/waymore/waymore.py -i ${TARGET} -mode U
	/usr/bin/cat "/opt/waymore/results/${TARGET}/waymore.txt" >> ${WAYBACK_DIR}/url_extract.txt
	/usr/bin/cat "${WAYBACK_DIR}/url_extract.txt" | grep "?" | urldedupe -m "s,qs" > ${WAYBACK_DIR}/params.txt
	/usr/local/bin/pathi_generator "${WAYBACK_DIR}/params.txt" | urldedupe > ${NUCLEI_DIR}/paths.txt
fi

if [ -f "${WAYBACK_DIR}/params.txt" ]; then
	types=( "lfi" "sqli" "xss" "rce" "ssti" )
	for scan_type in "${types[@]}"
	do
		printf "${BLUE}Creating target file for [${scan_type}]${RESET}"
		# create target files
		/usr/bin/cat ${WAYBACK_DIR}/params.txt | gf ${scan_type} > ${NUCLEI_DIR}/targets_${scan_type}.txt
		# create payload files
		printf "${BLUE}Creating payloads for [${scan_type}]${RESET}"
		payloads_generator ${NUCLEI_DIR}/targets_${scan_type}.txt ${WORDLIST_DIR}/${scan_type}.txt > ${NUCLEI_DIR}/nuclei_${scan_type}.txt
		# run nuclei
		printf "${BLUE}Running nuclei for [${scan_type}]${RESET}"
		nuclei -l ${NUCLEI_DIR}/nuclei_${scan_type}.txt -t ${NUCLEI_TEMPLATES}/${scan_type}/ -o ${NUCLEI_OUTPUT_DIR}/${scan_type}.txt -silent

		if [ ${scan_type} == "lfi" ] && [ -f "${NUCLEI_DIR}/paths.txt" ]; then
			printf "${BLUE}Running nuclei for [path traversal]${RESET}"
			nuclei -l ${NUCLEI_DIR}/paths.txt -t ${NUCLEI_TEMPLATES}/lfi_path/ -o ${NUCLEI_OUTPUT_DIR}/lfi_path.txt -silent
		fi
		if [ ${scan_type} == "sqli" ] && [ -f "${NUCLEI_DIR}/paths.txt" ]; then
			printf "${BLUE}Running nuclei for [sql path injection]${RESET}"
			nuclei -l ${NUCLEI_DIR}/paths.txt -t ${NUCLEI_TEMPLATES}/sqli_path/ -o ${NUCLEI_OUTPUT_DIR}/sqli_path.txt -silent
		fi
	done

	# sending results to discord
	results_lfi1=`wc -l $NUCLEI_OUTPUT_DIR/lfi.txt | awk '{print $1}' || echo 0`
	results_lfi2=`wc -l $NUCLEI_OUTPUT_DIR/lfi_path.txt | awk '{print $1}' || echo 0`
	results_sqli1=`wc -l $NUCLEI_OUTPUT_DIR/sqli.txt | awk '{print $1}' || echo 0`
	results_sqli2=`wc -l $NUCLEI_OUTPUT_DIR/sqli_path.txt | awk '{print $1}' || echo 0`
	results_xss=`wc -l $NUCLEI_OUTPUT_DIR/xss.txt | awk '{print $1}' || echo 0`
	results_rce=`wc -l $NUCLEI_OUTPUT_DIR/rce.txt | awk '{print $1}' || echo 0`
	results_ssti=`wc -l $NUCLEI_OUTPUT_DIR/ssti.txt | awk '{print $1}' || echo 0`

	/usr/bin/curl -k -X POST "https://discord.com/api/webhooks/$DISCORD_ID/$DISCORD_TOKEN" -H 'Content-Type: application/json' -d "{\"embeds\": [{\"title\":\"Vulnerability Scan Report\", \"color\":\"15158332\", \"fields\": [{\"name\":\"Program\", \"value\":\"${TARGET}\"}, {\"name\":\"LFI\", \"value\":\"LFI: ${results_lfi1}\\nPath_Injection: ${results_lfi2}\"},{\"name\":\"SQLi\",\"value\":\"SQLi: ${results_sqli1}\\nPath_Injection: ${results_sqli2}\"}, {\"name\":\"XSS\", \"value\":\"${results_xss}\"}, {\"name\":\"RCE\", \"value\":\"${results_rce}\"}, {\"name\":\"SSTI\", \"value\":\"${results_ssti}\"}]}]}"
fi



# Exiting
printf "${BLUE}Done${RESET}"
