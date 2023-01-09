#!/bin/bash

domain=$1
mkdir -p /root/Desktop/$domain/
# if [ -z "$1" ]; then
#   echo "Error: Please provide a domain as an argument. & No arguments supplied, kindly type -h for help."
#   exit 1
# fi

find /root/Desktop/$domain -name "freq.go" > a.txt
c=$(cat a.txt | wc -l )

install () {

	if [[ $c == 0 ]]; then
		
echo 'package main

import (
	"sync"
	"bufio"
	"net/http"
	"fmt"
	"os"
	"strings"
	"io/ioutil"
)

func main(){
	// fmt.Println("\n")
	fmt.Println("frequester tool By kraken !!")
	fmt.Println("\\__(-_-)__/")
	// fmt.Println("\n")

	colorReset := "\033[0m"
	colorRed := "\033[31m"
    colorGreen := "\033[32m"


	sc := bufio.NewScanner(os.Stdin)

	jobs := make(chan string)
	var wg sync.WaitGroup

	for i:= 0; i < 20; i++{

		wg.Add(1)
		go func(){
			defer wg.Done()
			for domain := range jobs {

				resp, err := http.Get(domain)
				if err != nil{
					continue
				}
				body, err := ioutil.ReadAll(resp.Body)
				if err != nil {
	      			fmt.Println(err)
	   			}
	   			sb := string(body)
	   			check_result := strings.Contains(sb , "alert(1)")
	   			// fmt.Println(check_result)
	   			if check_result != false {
	   				fmt.Println(string(colorRed),"Vulnerable To XSS:", domain,string(colorReset))
	   			}else{
	   				fmt.Println(string(colorGreen),"Not Vulnerable To XSS:", domain, string(colorReset))
	   			}

			}
			
   		}()

	}



	for sc.Scan(){
		domain := sc.Text()
		jobs <- domain		
		

	}
	close(jobs)
	wg.Wait()
}'> /root/Desktop/$domain/freq.go

	else
		echo 'file allready exist'
	


	fi
}
install

rm -rf a.txt



echo "Finding subdomains with crt.sh..."
python3 /root/Desktop/crt.py -d $domain | tee -a /root/Desktop/$domain/$1_subdomain.txt

echo "Finding subdomains with assetfinder..."
assetfinder -subs-only $domain | tee -a /root/Desktop/$domain/$1_subdomain.txt

echo "Finding subdomains with findomain..."
findomain -t $domain | tee -a /root/Desktop/$domain/$1_subdomain.txt

echo "Finding subdomains with subfinder..."
subfinder -d $domain -silent | tee -a /root/Desktop/$domain/$1_subdomain.txt

echo "Finding subdomains with sublist3r..."
sublist3r -d $domain -o /root/Desktop/$domain/$1_sublister.txt

echo "merge all domain files & delete duplicate domain..."
cat /root/Desktop/$domain/$1_subdomain.txt /root/Desktop/$domain/$1_sublister.txt | sort -u > /root/Desktop/$domain/$1_all_subdomain.txt

echo "clean all extra word..."
sed -i 's/Searching in the AnubisDB API... 🔍//g' /root/Desktop/$domain/$1_all_subdomain.txt
sed -i 's/Searching in the Archive.org API... 🔍//g' /root/Desktop/$domain/$1_all_subdomain.txt
sed -i 's/Searching in the CertSpotter API... 🔍//g' /root/Desktop/$domain/$1_all_subdomain.txt
sed -i 's/Searching in the Crtsh database API... 🔍//g' /root/Desktop/$domain/$1_all_subdomain.txt
sed -i 's/Searching in the Sublist3r API... 🔍//g' /root/Desktop/$domain/$1_all_subdomain.txt
sed -i 's/Searching in the Threatcrowd API... 🔍//g' /root/Desktop/$domain/$1_all_subdomain.txt
sed -i 's/Searching in the Threatminer API... 🔍//g' /root/Desktop/$domain/$1_all_subdomain.txt
sed -i 's/Searching in the Urlscan.io API... 🔍//g' /root/Desktop/$domain/$1_all_subdomain.txt
sed -i 's/Target ==> $1//g' /root/Desktop/$domain/$1_all_subdomain.txt
sed -i 's/Job finished in  seconds.//g' /root/Desktop/$domain/$1_all_subdomain.txt
sed -i 's/Good luck Hax0r 💀!//g' /root/Desktop/$domain/$1_all_subdomain.txt
sed -i '/^[[:space:]]*$/d' /root/Desktop/$domain/$1_all_subdomain.txt

echo "Finding all live valid subdomain..."
cat /root/Desktop/$domain/$1_all_subdomain.txt | httprobe | tee -a /root/Desktop/$domain/$1_host_sub.txt

echo "Work Complete.. we collect all working domain with link 0.0"




# cat /root/Desktop/$domain/$1_all_subdomain.txt | httprobe | tee -a /root/Desktop/$domain/$1_host_sub.txt




# cat /root/Desktop/$domain/$1_subdomain.txt | sort -u > /root/Desktop/$domain/$1_all_subdomain.txt
