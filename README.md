# Born2beRoot
February 28, 2022.

author : Marouane Benbajja - MAR BEN.
---
This project consists of having you set up your first server by following specific rules.
---
#🔴 Pairing this README with research will give you another level of knowledge and experience. 🔴

### Installation of virtual machine (with virtualbox):

- Video of installation : [see](https://www.youtube.com/watch?v=2w-2MX5QrQw)

### **What virtualization means ?**

---

- **Virtualization** a modern technique began in late 1960s it wasn’t widely adopted until the early 2000s. It means to create a **version** of something, including virtual platforms, devices and computer network resources.
    - Hardware virtualization or platform virtualization is creating a virtual machine that acts like a real computer with an OS (operating system). The software executed in these VM is separated form the hardware resources. In hardware virtualization the host machine is the machine that is used by the virtualization - the bare machine that you use (your computer, server, ...) - and the guest is the VM - that runs the guest OS in your machine -. The host ⇒ Software that runs the physical machine. The guest ⇒ Software that runs the VM. The software or [**firmware**](https://en.wikipedia.org/wiki/Firmware) that creates the VM on the host machine is called a **hypervisor** or *virtual machine monitor*.
    - **Virtual machine,** is the concept of installing an operating system that expects that is installed on a real computer. The VMs behaves exactly like real computers (physical computers) and depends on a virtual resources that are provided by the host machine (the machine where the VM is running). The virtual resources reserves part of the physical resources to provide it to the guests ( the hosted virtual machines ), the resources are isolated from the system hardware, this concept is made by a software called **hypervisor**.

### What is a hypervisor

---

- **Hypervisor** is a software, known as a virtual machine monitor, that runs VMs. A hypervisor allows to one host physical machine to supports multiple guest by sharing its resources, such as memory and processing.
    - **Benefits of hypervisors :**
        - ***Speed :*** It allow to create VMs instantly.
        - ***Efficiency :*** It minimize the cost and energy by allowing to install several VMs on one physical machine resources and more efficient use of the physical machine.
        - ***Flexibility :*** Bare-metal hypervisors allow VM’s OS and their Apps to run on variety of hardware types, because the hypervisor separates the OS form the main hardware, so the software doesn’t relies on specific hardware.
        - ***Portability :*** The isolation, from the physical machine, that the hypervisor can provide to the multiple VMs resided in the host gives the portability capacity. When an application needs more processing power, the virtualization software allows it to seamlessly access additional machines.
    - **Types of hypervisors :**
        - ***Type 1 (bare metal)*** ***:*** Acts like a lightweight operating system and runs directly on the host hardware, so there is no other layer between the hypervisor and the hardware, it is more secure and isolated from the attack-prone operating system and perform better and more efficiently. For these reasons it is usually used for data center computing needs.
        - ***Type 2 (hosted) :*** Called hosted because they run on top of operating system of the host machine, they are a software run on a the host OS, additional OS can be installed on top of hypervisor (VMs). The latency of this type is higher than the first one, because the communication between the hardware and hypervisor pass through extra layer of the OS. This type is known as client hypervisors, it is usually used with end users where higher latency doesn’t matter.
    - **How does a hypervisor work :**
        
        Hypervisor supports the creation and management of VM by abstracting a computer’s software from its hardware. By translating requests from physical to virtual resources (CPU, RAM, and network) and vice versa, hypervisors make virtualization possible.
        

### what is the difference between Debian and Cent-Os? Uses of Debian

---

- They are two based OS on Linux.

### Debian

---

- Comprehensive installer and easy upgrading
- Supports many architectures
- Has more packages
- Debian is fast catching up
- DEB package format & dpkg/APT as package manger
- EXT4 filesystem & ext2/3, NFSv3/4, SMB, GFS2, ZFS and many more
- Debian uses advanced packaging tool (apt) to manage packaging system.

### CentOs

---

- Hard To update
- More stable and supported by a large community
- RPM package format & YUM/DNF as package manger
- XFS filesystem & ext2/3, NFSv3/4, btrfs, SMB, GFS2 and many more

### What is LVM ? What is a partition table ? What is the difference between primary and logical partitions ? What is a mount point for partition ?

---

- **LVM** stand for **Logical Volume Manager**. It is a type of storage virtualization that allows managing logical volumes, filesystem, it is more advanced and flexible than the traditional whys of partitioning disks then formatting that with filesystem. It can be used for nearly any mount point except `*/boot*`.
    - 3 concepts that LVM manages :
        - Volume groups : The collection of physical and logical volumes that can be named.
        - Physical volumes : Any physical storage device HDD, ..., or partition, that has been initialized as a physical volume with LVM.
        - Logical volumes : flexible volume that Can be extended and reduced, provided by the LVM.

### What is package manager and the difference between aptitude and apt and apt-get?

---

- **Package manager** is a software that manages, installs, uninstalls, and upgrades packages in Linux and UNIX environments. **Packages** are collection of files that are bundled together and can be installed or removed as a group (that can be apps, software or other files ...).
    - Package A depends on upon another package B : B is required for A to operate properly.
    - If a package A recommends another package B : B provides important additional functionality to A desired in most situations.
    - If a package A suggests another package B : B provides functionality may enhance A.
    - If a package A conflicts with another package B : The two packages can’t be installed at the same time.
    - If you want to check the installed packages in Debian :
        
        ```bash
        dpkg -l   #it lists all installed packages
        dpkg -l | grep package 
        #Then it greps the line and displayge the package if it existes 
        ```
        
- Debian uses advanced packaging tool (apt) to manage packaging system.
    - **APT** : command line without GUI (graphical user interface) and simple, using apt + install + package name; is enough to let apt do all the other work by searching sorting and installing dependencies for that package.
    - **APTITUDE :** high level package manager, is front-end to advanced packaging tool which adds a user interface to the functionality. It allow to the user to interact searching for packages, install or remove it. Created for **Debian** extends its functionality to **RPM (package manger)** base distribution as well.

### **Aptitude :**

- Vaster and integrates functionalities of apt-get and it’s other variants apt-mark , apt-cache... (Aptitude ≥= Apt ≥= Apt-get + Apt-mark ....).
- Aptitude handles lot more stuff than Apt, including functionalities of **apt-mark**
 and **apt-cache...**
- Aptitude has a interactive interface along with option of command-line operation by entering required commands.
- Aptitude automatically removes unused packages.
- Aptitude offers ‘why’ and ‘why not’ command
- Aptitude suggests which  package should you install or dependencies of other packages

### What is SE-Linux, App-armor ?

---

- **AppArmor** is a Mandatory Access Control (MAC) system which is a kernel (LSM) enhancement to confine programs to a limited set of resources. AppArmor's security model is to bind access control attributes to programs rather than to users. AppArmor confinement is provided via profiles loaded into the kernel, typically on boot.
    
    **N.B :** AppArmor confines programs according to a set of rules that specify what files a given program can access. Apparmor is used in Debian and Ubuntu distributions. 
    
    - **To view AppArmor’s status :**
        
        ```bash
        sudo apparmor_status
        ```
        
- **SE-Linux**; Security-Enhanced Linux is a security architecture for Linux systems
that allows administrators to have more control over who can access the system. SELinux defines access controls for the applications, processes, and files on a system. SE-Linux is used in Cent_Os.

## How to install sudo ?

---

- **sudo,** which is an acronym for “*superuser do” or “substitute user do”*, is a command that runs an elevated prompt without a need to change your identity. Depending on your settings in the `*/etc/sudoers*`file. Using sudo command require the user’s password. The sudoers privileges are specified in the `*/etc/sudoers*`file, so you can give every user or group privileges that you want, by run the following command and edit the file:
    
    ```bash
    sudo vi /etc/sudoers
    ```
    
    <aside>
    📁 username ALL=(ALL) ALL   //gives user "username" sudo access
    %wheel ALL=(ALL) ALL      //Gives all users that belong to the wheel group sudo access
    
    </aside>
    
- Why sudo? sudo is used to avoid using root user in your administrating staffs. Small mistake with the root user can be costly and it’s an irreversible step. So you need a solution that is sudo, that provides a simple user with the root power.
    
    ### Su command :
    
    ---
    
    Is an acronym for switch user or substitute user. It is a command used to switch to a particular user, you need to enter the user’s password, unless you are root.
    
    ```bash
    su -           #switch to the root
    su username    #switch to the user that have username
    ```
    
    ### Installing sudo :
    
    ---
    
    - **Login as root :**
    
    ```bash
    su -    #You log as a root
    ```
    
    - **Update and upgrade the software repository list, then install sudo :**
    
    ```bash
    apt-get update -y
    apt-get upgrade -y
    apt install sudo
    ```
    

### What is SSH ? And how it works ?

---

- **SSH**, also known as Secure Shell or Secure Socket Shell, is a network protocol that gives users, particularly system administrators, a secure way to access a computer over an unsecured network. In addition to providing strong encryption, can also be used to create secure tunnels for other application protocols. An SSH server, by default, listens on the standard Transmission Control Protocol (TCP) port 22.
- The most basic use of SSH is to connect to a remote host for a terminal session. The form of that command is the following:
    
    ```bash
    ssh UserName@SSHserver.example.com
    # if you want you add the port 
    ssh UserName@SSHserver.example.com -p port_nbr
    ```
    
    This command will cause the client to attempt to connect to the server named *server.example.com*, using the user ID *UserName.*
    
    If this is the first time negotiating a connection between the local host and the server, the user will be prompted with the remote host's public key fingerprint and prompted to connect, despite there having been no prior connection:
    
    ```bash
    The authenticity of host 'sample.ssh.com' cannot be established.
    DSA key fingerprint is 01:23:45:67:89:ab:cd:ef:ff:fe:dc:ba:98:76:54:32:10.
    Are you sure you want to continue connecting (yes/no)?
    ```
    
    Answering with yes; the session continues and the host key is stored in the local system's known_hosts file. This is a hidden file, stored by default in a hidden directory, called `*/.ssh/known_hosts*`, in the user's home directory.
    
    ### How to install SSH :
    
    ```bash
    sudo apt-get update             #update the software repository list
    sudo apt install openssh-server #install ssh server
    sudo service sshd status        #Checking ssh service* status should be active
    sudo systemctl status ssh       #Checking ssh server* status
    ```
    
    - **To stop, start or restart the ssh service** :
    
    ```bash
    sudo service ssh stop   #Stopping lasts until the next reboot.
    sudo service ssh start
    sudo service ssh restart
    ```
    
    - **Get the IP address :**
    
    ```bash
    ip a
    sudo ifconfig  
    #to use ifconfig you should install net-tools by: 
    sudo apt-get install -y net-tools
    ```
    
    - **How to config the default port**
        - Enter this file `/etc/ssh/sshd_config` using following command.
    
    ```bash
    sudo vim /etc/ssh/sshd_config    #use nano if vim isn't installed yet
    ```
    
             → find this line : #Port 22 → Then change it to : Port 4242 
    
    ```bash
    sudo service ssh restart         #restart the ssh's service*
    sudo systemctl restart ssh       #restart the ssh's server*
    ```
    
    - **Quit connection if you were connected to a machine via ssh:**
    
    ```bash
    exit
    ```
    

### What is UFW firewall ?

---

- For the longest time, the security of Linux was in the hands of iptables. They are powerful but complicated at the same time especially for new users. Wherefore the UFW (Uncomplicated Firewall) is coming as a front end for iptables to simplify working with it. UFW provides a much more user-friendly framework for managing netfilter and a command-line interface for working with the firewall. UFW has a few GUI tools too.
    - Iptable is a Linux command line firewall that allows system administrators to manage incoming and outgoing traffic via a set of configurable table rules, using a set of tables which have chains that contain set of built-in or user defined rules. Thanks to them a system administrator can properly filter the network traffic of his system.
- **Installing UFW :**
    
    ```bash
    sudo apt-get install ufw
    ```
    
- **Enabling UFW :**
    
    ```bash
    sudo ufw enable
    ```
    
- **Configure the rules :**
    
    ```bash
    sudo ufw allow ssh      #allowing port for ssh
    sudo ufw allow 4242     #allowing port 4242
    ```
    
- **Check the UFW status :**
    
    ```bash
    sudo ufw status          #Check the ufw status and its rules
    sudo ufw status verbose  #Same as command above + default firewall setting
    sudo ufw status numbered #Same as the first, with numbred rules
    ```
    
- **Delete a rule :**
    
    ```bash
    sudo ufw status numbered
    sudo ufw delete nbr_of_rule
    ```
    

1. Go to VirtualBox-> Choose the VM->Select Settings

2. Choose “Network”-> “Adapter 1"->”Advanced”->”Port Forwarding”

![1img.png](Bonr2BeRoo%20ddea7/1img.png)

3. Enter the values as shown:

![2img.png](Bonr2BeRoo%20ddea7/2img.png)

## How to implement a strong password policy :

---

### There is tow steps :

- **Password expiration :**
    
    ```bash
    sudo nano /etc/login.defs     #open the file, use vim if already installed
    ```
    
    - Find this path :
    
    ```bash
    PASS_MAX_DAYS 9999
    PASS_MIN_DAYS 0
    PASS_WARN_AGE 7
    #Change values to what you want
    PASS_MAX_DAYS 30     #max days of password expiration 30 day
    PASS_MIN_DAYS 2      #min days possible to change password before expiration
    PASS_WARN_AGE 7      #min days to receive a notification before expiration
    ```
    
- If you created users before setting this configurations, their password expiration wouldn’t be configured. So you should configure it manually using `**chage**` command
    - The **`chage`** command changes the number of days between password 
    changes and the date of the last password change. This information is used by the system to determine when a user must change the password.
    
    ```bash
    chage -l user         #displays the user password expiring properties
    sudo chage -M 30 user #changes the max days of expiration
    sudo chage -m 2 user  #changes the min allowed days to change password
    ```
    
- **To manage password policy you need the password quality checking library (libpam-pwquality), so it must be installed first**
    
    ```bash
    sudo apt-get install libpam-pwquality
    ```
    
- **After installation, you will start implementing the password policy. There is two ways to do that.**
    - **The first way** → using `*/etc/pam.d/common-password*` file :
        
        ```bash
        sudo nano /etc/pam.d/common-password  #use vim if it is already installed
        ```
        
        - To edit the minimum password length :
        
        ```bash
        #Search this line
        password [success=2 default=ignore] pam_unix.so obscure sha512
        #Add the minlen
        password [success=2 default=ignore] pam_unix.so obscure sha512 minlen=10
        ```
        
        - To modify the number of time to retry wrong password :
        
        ```bash
        #Search this line
        password    requisite         pam_pwquality.so retry=value
        #Change the retry's value to what you want
        password    requisite         pam_pwquality.so retry=3
        ```
        
        - To configure the character configuration :
        
        ```bash
        #Search this line
        password    requisite         pam_pwquality.so retry=value
        #Add the options :
        	lcredit=-1       #At least 1 lower case character.
        	ucredit=-1       #At least 1 upper case character.
        	dcredit=-1       #At least 1 digit character.
        	maxrepeat=3      #The max number of consecutive identical characters.
        	usercheck=0      #The password shouldn't contain the username.
        	enforce_for_root #Same policy for root users
        	difok=7          #At least 7 characters different of the old password .
        ```
        
        ![passwd security.png](Bonr2BeRoo%20ddea7/passwd_security.png)
        
        - The file must be look like that :
        
        ```bash
        password [success=2 default=ignore] pam_unix.so obscure sha512 minlen=10
        password    requisite     pam_pwquality.so retry=3 lcredit=-1 ucredit=-1
        dcredit=-1 maxrepeat=3 usercheck=0 enforce_for_root difok=7
        ```
        
        - Save the file.
    - **The second way** → using `*/etc/security/pwquality.conf*` file :
        
        ```bash
        sudo nano /etc/security/pwquality.conf #use vim if it is already installed
        ```
        
        - You will find all options commented and explained their role you need just to uncomment those you want and modify value if it’s necessary and save the file. And all the work is done.
- **Now reboot all to apply the configurations :**
    
    ```bash
    sudo reboot
    ```
    

## **How to add new user :**

---

```bash
sudo adduser user_name
#Then it opens a prompt enter the password and complete informations.
sudo useradd user_name
```

- **Adduser command :**
    - *SYNOPSIS* : `**adduser** [options] LOGIN`
    - add users to the system according to command line options and configuration information in *`/etc/adduser.conf`*. It is a high level tool. by default choosing Debian policy conformant UID and GID values, creating a home directory with skeletal configuration, running a custom script, and other features.
    
    💡 After executing the adduser command it will automatically opens a prompt asking to enter the password and after entering it you complete user information, user full name, phone...
    
    💡 The ‘**adduser**‘ is much similar to the **useradd** command because it is just a symbolic link to it.
    
- **Useradd command :**
    - *SYNOPSIS* : `useradd [options] LOGIN`
    - In Linux, a ‘**useradd**‘ command is a low-level utility that is used for adding/creating user accounts in **Linux** and other **Unix-like** operating systems.

## Adding or changing password for an existing user :

---

- The `*/etc/passwd*` file contains information about the users on the system. Each line describes a distinct user.
- How to check all local users :

```bash
cut -d: -f1 /etc/passwd
```

💡Some times we need to update or add new password for a user even if already existing or new created (added by [useradd](https://www.notion.so/Bonr2BeRoot-69f8648dc8e74d759664efe016795287)), we use `passwd` command :

```bash
sudo passwd user_name #It displays a prompet to enter and comfime the new password
```

- *SYNOPSIS* : **`passwd** [*options*] [*LOGIN*]`
- The **`passwd`** command changes passwords for user accounts. If the command is executed without username (login), then it will change the current connected user.

🔴 **How to delete a user :** Only the root or a user with sudo privileges can remove users.

```bash
userdel username       #delete the user
userdel -r username    #delete the user and the user's directory
```

## Creating new group :

---

- **To create a new group we use `groupadd` command :**
    
    ```bash
    sudo groupadd group_name
    ```
    
    - *SYNOPSIS* : `**groupadd** [OPTIONS] GROUPNAME`
    - When invoked, `groupadd` creates a new group using the options specified on the command line plus the default values specified in the `*/etc/login.defs*`file.
    - The command adds an entry for the new group to the `*/etc/group*` and `*/etc/gshadow*` files. Once the group is created, you can start adding users to the group.
    
    💡Only the root or a user with sudo privileges can create new groups.
    
    **🔴 How to delete a group :** Only the root or a user with sudo privileges can remove groups.
    
    ```bash
    groupdel group_name
    ```
    

## Adding users to a particular group :

---

- **To add a user to certain group**

```bash
sudo usermod -aG group_name username
sudo adduser user_name group_name
```

- *SYNOPSIS* : **`usermod** [*options*] *LOGIN*`
- After creating a user we have to sometimes change their attributes like password or login directory, add to groups etc. so in order to do that we use the `Usermod` command. The information of a user is stored in the following files:
    - `*/etc/passwd*`  -  `*/etc/group*`  -  `*/etc/shadow*`  -  `*/etc/login.defs*`  - `*/etc/gshad*` -  `*/etc/login.defs*`
    
    When we execute `usermod` command in terminal the command make the changes in these files itself.
    
    - **Note:** `usermod` command needs to be executed only as a **root** user.
    
    🔑 **-G**, **--groups***GROUP1*[*,GROUP2,...*[*,GROUPN*]]]
    
    - Add user to the group -or groups separated by comma without white spaces- assigned after -G option.
    
    **-a** : **--append**
    
    - Used only with -G, it appends the user to the group with saving his old old memberships in other groups. If using -G without -a the user will be added to the group but will be removed from the old ones.

## **To check the existence of the user in the group**

---

```bash
getent group group_name   #displays the existing users in the group
groups username
```

- **Getent command :**
    - *SYNOPSIS* : **`getent** [*OPTION*]... database... key...`
    - The getent command displays entries from databases supported by the Name Service Switch libraries, which are configured in `*/etc/nsswitch.conf*`.
        - The *database* may be any of library supported by the GNU C Library; like in our example : group - passwd - shadow....
        
        🔑 To check the group existence use :
        
        ```bash
        getent group
        ```
        
- **Groups command :**
    - SYNOPSIS : **`groups** [*OPTION*]... [*USERNAME*]...`
    - List all groups a user is a member of. Print group memberships for each USERNAME. Run ‘groups’ command without any arguments to display the list of groups associated with the **current user.**

## Set up configuration for sudo group

---

- To set up our configuration we need to edit the sudoers file `*/etc/sudoers`.*
    
    ```bash
    sudo nano /etc/sudoers  #use vim if is already installed
    ```
    
    - **To set the paths that can be used by sudo:**
    
    ```bash
    Defaults   secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin"
    ```
    
    - **Authentication using sudo has to be limited to 3 attempts if an incorrect password :**
    
    ```bash
    Defaults     passwd_tries=3
    ```
    
    - **A custom message to be displayed if an error due to a wrong password occurs when using sudo :**
    
    ```bash
    Defaults     badpass_message="Your message"  #Between "" add your message.
    ```
    
    - **Each action log file has to be saved in the /var/log/sudo/ folder :**
    
    ```bash
    Defaults	logfile="/var/log/sudo/sudo.log"
    Defaults	log_input,log_output
    ```
    
    - **Enabling TTY mode :**
    
    ```bash
    Defaults        requiretty
    ```
    
     → Why TTY : **tty** is a command in Unix and Unix-like operating systems to print the file name of the terminal connected to standard input. It is commonly used to check if the output medium is a terminal. If no file is detected (in case, it's being run as part of a script or the command is being piped) `not a tty` is printed to stdout and the command exits with an exit status of 1.
    
    → In other words, in our example it imposes that the communication with the VM should be with a terminal ⇒ that is equivalent that the communication is between a human and the VM.
    
    → Require tty: (*Why use tty? If some non-root code is exploited (a PHP script, for example), the `requiretty` option means that the exploit code won't be able to directly upgrade its privileges by running `sudo`.*)
    
- The file will look like this :

```bash
Defaults   secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin"
Defaults   passwd_tries=3
Defaults   badpass_message="Wrong password, try again!!"
Defaults	 logfile="/var/log/sudo/sudo.log"
Defaults	 log_input,log_output
Defaults   requiretty
```

![sudo config.png](Bonr2BeRoo%20ddea7/sudo_config.png)

- Save the file.

### How to change Hostname

---

- To check the current hostname of your VM, use `hostnamectl` command :
    
    ```bash
    hostnamectl       #displays all information about the host machine
    hostname          #displays the host name
    cat /proc/sys/kernel/hostname
    ```
    
    - *SYNOPSIS* : **`hostnamectl**[OPTIONS...] {COMMAND}`
    - `hostnamectl` may be used to query and change the system hostname and related settings.
- To change the hostname :
    - Execute the current command :
    
    ```bash
    sudo hostnamectl set-hostname new_hostname
    ```
    
    - Then edit the `*/etc/hosts*` file :
    
    ```bash
    sudo nano /etc/hosts  #use vim if already installed
    ```
    
    - Change old_hostname with new_hostname:
    
    ```bash
    #Before editing
    127.0.0.1       localhost
    127.0.0.1       old_hostname
    #After editing
    127.0.0.1       localhost
    127.0.0.1       new_hostname
    ```
    
- The reboot and check :

```bash
sudo reboot
#To avoid any problem of signature changing you can change the user the hostname
#will be changed and go bach to the previous user, without rebooting. 
```

## Building the monitoring script

---

- **To execute the monitoring.sh script every 10 minutes we should use the crontab (cron table) file.**
    - **Crontab** : stand for cron table, consists a list of command each by line, telling `cron` command what and when to run and is stored for users in `*/var/spool/cron*`. In other words, the **crontab** is a list of commands that you want to run on a regular schedule. Each user has their own crontab, and commands in any given crontab will be executed as the user who owns the crontab.
    - Linux Crontab Format :
    
    ```bash
    MIN HOUR DOM MON DOW CMD
    #This means :
    MIN      Minute field    0 to 59
    HOUR     Hour field      0 to 23
    DOM      Day of Month    1-31
    MON      Month field     1-12
    DOW      Day Of Week     0-6
    CMD      Command         Any command to be executed.
    # Note : * == all
    ```
    
    - **Cron** :The **`cron`** command-line utility, also known as **cron job**, is a job scheduler on Unix-like operating systems. Users who set up and maintain software environments use cron to schedule jobs (commands or shell scripts) to run periodically at fixed times, dates, or intervals.
- **Create the monitoring.sh file (it’s better to create it in `*/usr/local/bin/` file)*:**
    
    ```bash
    touch monitoring.sh
    ```
    
- **Building the script :**
    - **Architecture** : `uname -a`
        - ***uname*** : print system information
            - ***-a*** : print all information, in the following order.
    - **CPU physical** :  `grep “physical id” /proc/cpuinfo | uniq | wc -l`
        - ***grep*** : print lines matching a pattern.
        - ***uniq*** : report or omit repeated lines.
        - ***wc*** : print newline, word, and byte counts for each file.
            - ***-l*** : ******print the newline counts
    - **vCPU** : `grep "processor" /proc/cpuinfo | wc -l`
        - ***grep*** : print lines matching a pattern.
        - ***wc*** : print newline, word, and byte counts for each file.
            - ***-l*** : ******print the newline counts
    - **Memory Usage** : `free --mega | awk 'NR == 2 {printf("%d / %d MB \t (%.2f%%)\n", $3, $2, $3/$2*100)}'`
        - ***free*** : Display amount of free and used memory in the system.
            - ***—mega*** : show output in megabytes.
        - ***awk*** : pattern scanning and processing language
            - NR == 2 : it is a conditional expression, means if `NR` (number of the line) is 2 then the condition is valid and it can execute what comes after. Because we want to take the second line that `free` displays where there is the total and used RAM values.
            - Printf : it works exactly like the C printf.
            - `$2` or `$3` : means the to take the value of the filed number 2 or 3.
            - ***→ N.B*** : this whole command is for taking what `free` displays and search the second line, it will check every line until it finds the line number 2 the it will take the value of the 2nd and 3rd fields, the 3rd is the used RAM while 2nd is the total of RAM, it displays the 3rd then the 2nd then calculate the percentage and display it.
    - **Disk Usage** : `df --total -BG | awk '$1 == "total" {printf("%d / %d GB (%d%%)\n", $3, $2, $5)}'`
        - ***df*** : report file system disk space usage.
            - ***—total*** : produce a grand total of all partitions.
            - ***-BG*** : scale sizes by SIZE before printing them. E.g., `-BM' prints sizes in units of 1,048,576 bytes.
        - ***awk*** : pattern scanning and processing language.
            - `$1 == "total"`  : the line that contains the “total” word in the first colon
            - Printf : it works exactly like the C printf.
    - **CPU Load** : `top -bn1 | grep load | awk '{printf "%.2f%%\n", $(NF-2)}'`
        - ***top*** : display Linux tasks.
            - ***-bn1*** : Starts top in 'Batch mode', which could be useful for sending output from top to other programs or to a file. In this mode, top will not accept input and runs until the iterations limit you've set with the '-n' command-line option or until killed.
        - ***awk*** : pattern scanning and processing language.
            - Printf : it works exactly like the C printf.
            - $(NF-2) == Total number of fields in the line mines 2. The third last field.
    - **Last Boot** : `who -b | awk '$1 == "system" {print $3" "$4}'`
        - ***who*** : show who is logged on.
        - ***-b*** : time of last system boot.
        - ***awk*** : pattern scanning and processing language.
            - `$1 == "system"`  : the line that contains the “system” word in the first colon
            - `Print` : it prints the colons matched after $ sign.
    - **LVM Use ****: `lsblk | grep "lvm" | awk '{if ($1) {print "Yes";exit;} else {print "No"}}'`
        - ***lsblk*** : list block devices.
        - ***grep*** : print lines matching a pattern.
        - ***awk*** : pattern scanning and processing language.
            - if after `grep` the host components  and return a line that contains an “lvm” word then the `awk` will met this line and the if condition will be valid.
    - **Connexions TCP** : `cat /proc/net/sockstat | awk '$1 == "TCP:" {print $3 " ESTABLISHED"}'`
        - ***cat :*** concatenate files and print on the standard output.
        - ***awk*** : pattern scanning and processing language.
    - **User Log ****: `w -h | wc -l` **or** `users | wc -w` **or** `who | wc -l`
        - ***w*** : Show who is logged on and what they are doing.
            - ***-h*** : Don't print the header.
        - ***wc*** : print newline, word, and byte counts for each file.
            - ***-l*** : print the newline counts.
        - ***who*** : show who is logged on.
    - **Network** :
        - IP : `hostname -I`
            - *hostname* : show or set the system's host name.
                - *-I* : Display all network addresses of the host.
        - MAC addrs : `ip a | grep ether | awk '{print "("$2")"}'`
            - *ip a* : show / manipulate routing, devices, policy routing and tunnels.
    - **Sudo** : `grep COMMAND /var/log/sudo/sudo.log | wc -l`
- **The script looks like :**
    
    ```bash
    #!/bin/bash
    arc=$(uname -a)
    pcpu=$(grep "physical id" /proc/cpuinfo | uniq | wc -l)
    vcpu=$(grep "processor" /proc/cpuinfo | wc -l)
    mem=$(free --mega | awk 'NR == 2 {printf("%d / %d MB \t (%.2f%%)\n", $3, $2, $3/$2*100)}')
    disk=$(df --total -BG | awk '$1 == "total" {printf("%d / %d GB (%d%%)\n", $3, $2, $5)}')
    lcpu=$(top -bn1 | grep load | awk '{printf "%.2f%%\n", $(NF-2)}')
    lstboot=$(who -b | awk '$1 == "system" {print $3" "$4}')
    lvm=$(lsblk | grep "lvm" | awk '{if ($1) {print "Yes";exit;} else {print "No"}}')
    tcp=$(cat /proc/net/sockstat | awk '$1 == "TCP:" {print $3 " ESTABLISHED"}')
    log=$(w -h | wc -l)
    ip=$(hostname -I)
    mac=$(ip a | grep ether | awk '{print "("$2")"}')
    sudo=$(grep COMMAND /var/log/sudo/sudo.log | wc -l)
    wall "
    	#Architecture : $arc
    	#CPU Physical : $pcpu
    	#vCPU : $vcpu
    	#Memory Usage : $mem
    	#Disk Usage : $disk
    	#CPU Load : $lcpu
    	#Last Boot : $lstboot
    	#LVM Use : $lvm
    	#Connexions TCP : $tcp
    	#User Log : $log
    	#Network : IP $ip $mac
    	#Sudo : $sudo cmd"
    ```
    
- **Open sudoers file:**
    
    ```bash
    sudo visudo
    ```
    
- **Add this line:**
    
    ```bash
    your_username ALL=(ALL) NOPASSWD: /usr/local/bin/monitoring.sh
    ```
    
    ![sudoers nopasswd.png](Bonr2BeRoo%20ddea7/sudoers_nopasswd.png)
    
- **Reboot :**
    
    ```bash
    sudo reboot
    ```
    
- **Execute the script as su:**

```bash
sudo bash /usr/local/bin/monitoring.sh
```

- **Open crontab and add the rule:**

```bash
sudo crontab -u root -e
```

- **Add at end as follows: (*/10 means every 10 mins the script will show)**

```bash
*/10 *  *  *  * bash /usr/local/bin/monitoring.sh
#MIN H DOM M DOW CMD
# MIN      Minute field    0 to 59
# HOUR     Hour field      0 to 23
# DOM      Day of Month    1-31
# MON      Month field     1-12
# DOW      Day Of Week     0-6
# CMD      Command         Any command to be executed.
```

### What is every partition means ?

---

`/boot` : Boot loader files (e.g., kernels, initrd).

`/root` : Home directory for the root user.

`/home` : Users' home directories, containing saved files, personal settings, etc.

`/srv` : Site-specific data served by this system, such as data and scripts for web servers, data offered by FTP servers, and repositories for version control systems (appeared in FHS-2.3 in 2004).

`/tmp` : Directory for temporary files (see also /var/tmp). Often not preserved between system reboots and may be severely size-restricted.

`/var` : Variable files: files where the content of the file is expected to continually change during normal operation of the system, such as logs, spool files, and temporary e-mail files.

`/var/log` : Log files. Various logs.

`[SWAP]` : The swap partition serves as overflow space for your RAM. If your RAM fills up completely, any additional applications will run off the swap partition rather than RAM.
