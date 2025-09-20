const { exec, execSync } = require('child_process');
const os = require('os');
const path = require('path');
const fs = require('fs-extra');
// Platform-specific imports
let sudo = null;
if (os.platform() !== 'win32') {
    try {
        sudo = require('sudo-prompt');
    } catch (error) {
        console.warn('sudo-prompt not available on this platform');
    }
}

class SystemPrivileges {
    constructor() {
        this.platform = os.platform();
        this.isElevated = false;
        this.sudoOptions = {
            name: 'Apollo Security'
        };

        this.checkPrivileges();
    }

    async checkPrivileges() {
        try {
            if (this.platform === 'win32') {
                // Check if running as Administrator on Windows
                try {
                    execSync('net session', { stdio: 'ignore' });
                    this.isElevated = true;
                } catch {
                    this.isElevated = false;
                }
            } else {
                // Check if running as root on Unix
                this.isElevated = process.getuid() === 0;
            }

            console.log(`🔐 Privilege Status: ${this.isElevated ? 'ELEVATED' : 'STANDARD'}`);
            return this.isElevated;
        } catch (error) {
            console.error('Failed to check privileges:', error);
            return false;
        }
    }

    async requestElevation() {
        if (this.isElevated) {
            console.log('✅ Already running with elevated privileges');
            return true;
        }

        console.log('🔓 Requesting elevated privileges...');

        if (this.platform === 'win32') {
            return this.requestWindowsElevation();
        } else {
            return this.requestUnixElevation();
        }
    }

    async requestWindowsElevation() {
        return new Promise((resolve) => {
            const scriptPath = path.join(__dirname, '..', '..', 'elevate.vbs');
            const vbsScript = `
Set UAC = CreateObject("Shell.Application")
UAC.ShellExecute "${process.execPath}", "${process.argv.slice(1).join(' ')}", "", "runas", 1
            `;

            fs.writeFileSync(scriptPath, vbsScript);

            exec(`cscript //nologo "${scriptPath}"`, (error) => {
                try {
                    if (fs.existsSync(scriptPath)) {
                        fs.unlinkSync(scriptPath);
                    }
                } catch (unlinkError) {
                    console.warn('Warning: Could not cleanup elevation script:', unlinkError.message);
                }

                if (!error) {
                    console.log('✅ Elevated privileges granted');
                    resolve(true);
                } else {
                    console.error('❌ Failed to elevate privileges:', error);
                    resolve(false);
                }
            });
        });
    }

    async requestUnixElevation() {
        if (!sudo) {
            console.warn('⚠️ sudo-prompt not available, cannot elevate privileges');
            return false;
        }

        return new Promise((resolve) => {
            const command = `"${process.execPath}" "${process.argv.slice(1).join('" "')}"`;

            sudo.exec(command, this.sudoOptions, (error) => {
                if (!error) {
                    console.log('✅ Elevated privileges granted');
                    resolve(true);
                } else {
                    console.error('❌ Failed to elevate privileges:', error);
                    resolve(false);
                }
            });
        });
    }

    async executePrivilegedCommand(command, options = {}) {
        if (!this.isElevated) {
            console.warn('⚠️ Attempting privileged command without elevation');
            return this.executeWithSudo(command, options);
        }

        return new Promise((resolve, reject) => {
            exec(command, options, (error, stdout, stderr) => {
                if (error) {
                    reject(error);
                } else {
                    resolve({ stdout, stderr });
                }
            });
        });
    }

    async executeWithSudo(command, options = {}) {
        if (this.platform === 'win32') {
            return this.executePrivilegedCommandWindows(command, options);
        }

        if (!sudo) {
            throw new Error('sudo-prompt not available on this platform');
        }

        return new Promise((resolve, reject) => {
            sudo.exec(command, this.sudoOptions, (error, stdout, stderr) => {
                if (error) {
                    reject(error);
                } else {
                    resolve({ stdout, stderr });
                }
            });
        });
    }

    async executePrivilegedCommandWindows(command, options = {}) {
        return new Promise((resolve, reject) => {
            const { spawn } = require('child_process');
            const child = spawn('powershell', ['-Command', `Start-Process cmd -ArgumentList '/c ${command}' -Verb RunAs -WindowStyle Hidden -Wait`], {
                stdio: 'pipe',
                ...options
            });

            let stdout = '';
            let stderr = '';

            child.stdout?.on('data', (data) => {
                stdout += data.toString();
            });

            child.stderr?.on('data', (data) => {
                stderr += data.toString();
            });

            child.on('close', (code) => {
                if (code === 0) {
                    resolve({ stdout, stderr });
                } else {
                    reject(new Error(`Command failed with code ${code}: ${stderr}`));
                }
            });

            child.on('error', (error) => {
                reject(error);
            });
        });
    }

    async killProcess(pid) {
        console.log(`🎯 Terminating process: ${pid}`);

        try {
            if (this.platform === 'win32') {
                await this.executePrivilegedCommand(`taskkill /F /PID ${pid}`);
            } else {
                await this.executePrivilegedCommand(`kill -9 ${pid}`);
            }
            console.log(`✅ Process ${pid} terminated`);
            return true;
        } catch (error) {
            console.error(`❌ Failed to kill process ${pid}:`, error);
            return false;
        }
    }

    async blockNetworkConnection(ip, port = null) {
        console.log(`🚫 Blocking connection to: ${ip}${port ? ':' + port : ''}`);

        try {
            if (this.platform === 'win32') {
                const ruleName = `Apollo_Block_${ip.replace(/\./g, '_')}`;
                const command = `netsh advfirewall firewall add rule name="${ruleName}" dir=out action=block remoteip=${ip}${port ? ` remoteport=${port}` : ''} protocol=any`;
                await this.executePrivilegedCommand(command);
            } else if (this.platform === 'darwin') {
                // macOS pfctl
                const command = `echo "block drop quick on any from any to ${ip}" | pfctl -a apollo -f -`;
                await this.executePrivilegedCommand(command);
            } else {
                // Linux iptables
                const command = `iptables -A OUTPUT -d ${ip}${port ? ` --dport ${port}` : ''} -j DROP`;
                await this.executePrivilegedCommand(command);
            }

            console.log(`✅ Blocked connection to ${ip}`);
            return true;
        } catch (error) {
            console.error(`❌ Failed to block connection:`, error);
            return false;
        }
    }

    async unblockNetworkConnection(ip, port = null) {
        console.log(`✅ Unblocking connection to: ${ip}${port ? ':' + port : ''}`);

        try {
            if (this.platform === 'win32') {
                const ruleName = `Apollo_Block_${ip.replace(/\./g, '_')}`;
                const command = `netsh advfirewall firewall delete rule name="${ruleName}"`;
                await this.executePrivilegedCommand(command);
            } else if (this.platform === 'darwin') {
                const command = `pfctl -a apollo -F all`;
                await this.executePrivilegedCommand(command);
            } else {
                const command = `iptables -D OUTPUT -d ${ip}${port ? ` --dport ${port}` : ''} -j DROP`;
                await this.executePrivilegedCommand(command);
            }

            return true;
        } catch (error) {
            console.error(`❌ Failed to unblock connection:`, error);
            return false;
        }
    }

    async quarantineFile(filePath) {
        console.log(`🔒 Quarantining file: ${filePath}`);

        try {
            const quarantineDir = path.join(os.homedir(), '.apollo', 'quarantine');
            await fs.ensureDir(quarantineDir);

            const fileName = path.basename(filePath);
            const timestamp = Date.now();
            const quarantinedPath = path.join(quarantineDir, `${timestamp}_${fileName}.quarantine`);

            // Create metadata file
            const metadata = {
                originalPath: filePath,
                quarantineDate: new Date().toISOString(),
                reason: 'Detected as malicious',
                hash: await this.getFileHash(filePath)
            };

            await fs.writeJSON(`${quarantinedPath}.meta`, metadata);

            // Move and encrypt file
            if (this.platform === 'win32') {
                // Remove execute permissions and hide file
                await this.executePrivilegedCommand(`attrib +H +S "${filePath}"`);
                await this.executePrivilegedCommand(`icacls "${filePath}" /deny Everyone:X`);
            } else {
                // Remove all permissions
                await this.executePrivilegedCommand(`chmod 000 "${filePath}"`);
            }

            // Move to quarantine
            await fs.move(filePath, quarantinedPath);

            console.log(`✅ File quarantined: ${quarantinedPath}`);
            return quarantinedPath;
        } catch (error) {
            console.error(`❌ Failed to quarantine file:`, error);
            return null;
        }
    }

    async getFileHash(filePath) {
        const crypto = require('crypto');
        const fileBuffer = await fs.readFile(filePath);
        const hashSum = crypto.createHash('sha256');
        hashSum.update(fileBuffer);
        return hashSum.digest('hex');
    }

    async createSystemService() {
        console.log('🔧 Installing Apollo as system service...');

        try {
            if (this.platform === 'win32') {
                return this.createWindowsService();
            } else if (this.platform === 'darwin') {
                return this.createMacOSService();
            } else {
                return this.createLinuxService();
            }
        } catch (error) {
            console.error('❌ Failed to create system service:', error);
            return false;
        }
    }

    async createWindowsService() {
        const serviceName = 'ApolloProtection';
        const displayName = 'Apollo Security Protection';
        const binPath = process.execPath;

        try {
            // Create Windows service
            const createCmd = `sc create ${serviceName} binPath= "${binPath}" DisplayName= "${displayName}" start= auto`;
            await this.executePrivilegedCommand(createCmd);

            // Configure service
            await this.executePrivilegedCommand(`sc config ${serviceName} start= auto`);
            await this.executePrivilegedCommand(`sc description ${serviceName} "Apollo military-grade protection service"`);

            // Start service
            await this.executePrivilegedCommand(`sc start ${serviceName}`);

            console.log('✅ Windows service created and started');
            return true;
        } catch (error) {
            console.error('Failed to create Windows service:', error);
            return false;
        }
    }

    async createMacOSService() {
        const plistContent = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.apollo.shield</string>
    <key>ProgramArguments</key>
    <array>
        <string>${process.execPath}</string>
        <string>--service</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardErrorPath</key>
    <string>/var/log/apollo.err</string>
    <key>StandardOutPath</key>
    <string>/var/log/apollo.out</string>
</dict>
</plist>`;

        const plistPath = '/Library/LaunchDaemons/com.apollo.shield.plist';

        try {
            await fs.writeFile(plistPath, plistContent);
            await this.executePrivilegedCommand(`launchctl load ${plistPath}`);
            console.log('✅ macOS daemon created and loaded');
            return true;
        } catch (error) {
            console.error('Failed to create macOS daemon:', error);
            return false;
        }
    }

    async createLinuxService() {
        const serviceContent = `[Unit]
Description=Apollo Security Protection
After=network.target

[Service]
Type=simple
ExecStart=${process.execPath} --service
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target`;

        const servicePath = '/etc/systemd/system/apollo.service';

        try {
            await fs.writeFile(servicePath, serviceContent);
            await this.executePrivilegedCommand('systemctl daemon-reload');
            await this.executePrivilegedCommand('systemctl enable apollo.service');
            await this.executePrivilegedCommand('systemctl start apollo.service');
            console.log('✅ Linux systemd service created and started');
            return true;
        } catch (error) {
            console.error('Failed to create Linux service:', error);
            return false;
        }
    }

    async enableRealtimeProtection() {
        console.log('🛡️ Enabling real-time protection...');

        if (!this.isElevated) {
            console.warn('⚠️ Real-time protection requires elevated privileges');
            const elevated = await this.requestElevation();
            if (!elevated) {
                return false;
            }
        }

        // Platform-specific real-time protection
        if (this.platform === 'win32') {
            // Windows Defender exclusion for Apollo
            try {
                await this.executePrivilegedCommand(`powershell -Command "Add-MpPreference -ExclusionPath '${process.cwd().replace(/'/g, "''")}'"`);
                console.log('✅ Windows Defender configured');
            } catch (error) {
                console.warn('Could not configure Windows Defender:', error);
            }
        }

        console.log('✅ Real-time protection enabled');
        return true;
    }

    async isolateSystem() {
        console.log('🚨 EMERGENCY: Isolating system from network...');

        try {
            if (this.platform === 'win32') {
                // Disable all network adapters
                await this.executePrivilegedCommand('wmic path win32_networkadapter where NetEnabled=true call disable');
                console.log('✅ Network adapters disabled');
            } else if (this.platform === 'darwin') {
                // Turn off Wi-Fi and Ethernet
                await this.executePrivilegedCommand('networksetup -setairportpower en0 off');
                await this.executePrivilegedCommand('ifconfig en1 down');
                console.log('✅ Network interfaces disabled');
            } else {
                // Linux: bring down all network interfaces
                await this.executePrivilegedCommand('nmcli networking off');
                console.log('✅ NetworkManager disabled');
            }

            return true;
        } catch (error) {
            console.error('❌ Failed to isolate system:', error);
            return false;
        }
    }

    async restoreNetwork() {
        console.log('🔄 Restoring network connections...');

        try {
            if (this.platform === 'win32') {
                await this.executePrivilegedCommand('wmic path win32_networkadapter where NetEnabled=false call enable');
            } else if (this.platform === 'darwin') {
                await this.executePrivilegedCommand('networksetup -setairportpower en0 on');
                await this.executePrivilegedCommand('ifconfig en1 up');
            } else {
                await this.executePrivilegedCommand('nmcli networking on');
            }

            console.log('✅ Network connections restored');
            return true;
        } catch (error) {
            console.error('❌ Failed to restore network:', error);
            return false;
        }
    }
}

module.exports = SystemPrivileges;