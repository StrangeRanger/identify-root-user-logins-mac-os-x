This program scans system.log in order to find out if a user(s) have logged in as root, and identify who they are.

Security Features/Notes:
- This program identifies user who have used `sudo bash`, `sudo -i`, `sudo su`, and `su`/`su root`
- If a user on the system created a temporary account in order to log in as root, then deletes the account after he or she is done with it, the temporary account will still show up in the scan results.
- Any and all users who use `sudo su` to change to another user will be marked/identified. This makes it easier to identify a user who tries to blame a different user for logging in as root. (see Program Notes/Faults below)
- Any and all users who attempt to either log into the root account or switch users, and are unsuccessful, will be identified and marked down.

Program Notes/Faults:
- If a user with sudo power creates a tmp user and switches to that user, or even an excisting user, any `sudo` or `su` commands executed will cause the switched user to be blamed instead of the actual person. Though the culprit must know the password of the user he/she is switching to to successfully execute any `sudo` or `su` commands. Since this program identifies individuals who use `sudo su`,
in combination with this program and searching through logs, you will be able to find out who the culprit was.
- Small error: if user inputs their sudo password correctly when executing `sudo su {username}`, but the username does not exist, they will still be marked as `{username} has switched users {X} time(s)`. A good method in making sure that the user did switch users is check the /var/log/auth.log under the date that the incident occured. Take a look at `root_login_check.odt` to know what to look for.

Other Notes:
- By default, the auth.log will be scanned up to 7 days worth of logs. If you wish to change the number of days, change teh value of N in the script.

This program only works on macOS .
Verisons of macOS that this script works on:
- Yosemity: Works
- El Capitan: Works
- Sierra: Unkown
- High Sierra: Unkown
- Mojave: Unkown 
