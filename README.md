# iOS Keychain Decrypter 
Small script to decrypt keychains on iOS.
Needs an agent on the iDevice to unwrap keys. Rest of decryption/parsing id done on host

Tested on an iPhone 7 iOS 14.0 

This works on MacOS Catalina and should work on Linux
Windows support may require to adapt ssh commandlines

## Requirements
```
brew install hudochenkov/sshpass/sshpass # Install sshpass which is script use.
pipenv shell
pipenv install # this will install python package which in Pipfile
```
Jailbroken device accessible via ssh (default checkra1n behaviour)
`sshpass`, `ssh` and `iproxy` configured in your PATH

To compile phone agent, Xcode should be installed.

## Dump my keychain
1. jailbreak your device 
2. run iproxy in a terminal mapping localport 2222 - for checkra1ned devices:
```
iproxy 2222 44
```
4. open a new terminal window
5. Upload the agent on your device
```
sshpass -p alpine scp -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -P2222 keyclass_unwrapper root@localhost:
```
6. Download keychain database from your device
```
sshpass -p alpine scp -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -P2222 root@localhost:/private/var/Keychains/keychain-2.db .
```
7. **unlock your device and keep it unlocked** until the dump is finished
8. run the python script
```
python3 keychain_decrypt.py
```
9. You should obtain a keychain_decrypted.plist file
If an error occure, try again, sometimes it is a timing problem

10. Clean
```
sshpass -p alpine ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -p2222 root@localhost "rm /var/root/keyclass_unwrapper; shutdown -h now"
```

## Self compile the agent
You should have an identity to sign the code
```
make
```

## Credits
- [iChainbreaker](https://github.com/n0fate/iChainbreaker)
- [iphone-dataprotection.keychainviewer]( )https://github.com/nabla-c0d3/iphone-dataprotection.keychainviewer/tree/master/Keychain)
- [Apple Open Sources]( )https://opensource.apple.com/source/Security/Security-59306.80.4/keychain/securityd/)

## Licence
GPL V2

