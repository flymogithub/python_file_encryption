import requests
import hashlib

dataFile = "/home/developer/Development/data/checkfile.csv"
compFile = "/home/developer/Development/data/compromised_passwords.txt"

def check_passwords():
    with open(dataFile, 'r') as file:
        passwords = file.readlines()
    
    wfile = open(compFile, 'w')

    for password in passwords:
        password = password.strip()
        sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()

        hash_response = requests.get(f"https://api.pwnedpasswords.com/range/{sha1_password[:5]}")
        
        if hash_response.status_code == 200:
            hashes = (line.split(':') for line in hash_response.text.splitlines())
            
            found = any(h[0] == sha1_password[5:].upper() for h in hashes)
            
            if found:
                print(f"Password '{password}' has been compromised.")
                wfile.write(password + '\n')
            #else:
            #    print(f"Password '{password}' is safe.")
        else:
            print(f"Error checking password '{password}': {response.status_code}")
    wfile.close()
if __name__ == "__main__":
    check_passwords()
# password_checker.py
