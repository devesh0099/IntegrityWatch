SM_REMOTESESSION = 0x1000 # Windows API RemoteSessionKey

# Processes to block/flag
PROCESS_BLOCKLIST = {
    "commercial_tools": {
        "TeamViewer.exe", "TeamViewer_Service.exe", "tv_w32.exe", "tv_x64.exe",
        "AnyDesk.exe", "ad.exe",
        "LogMeIn.exe", "LogMeInSystray.exe", "LMIGuardian.exe",
        "GoToMeeting.exe", "g2mcomm.exe",
        "Splashtop.exe", "SRServer.exe", "SRService.exe",
        "Supremo.exe", "SupremoService.exe",
        "RustDesk.exe",
        "AeroAdmin.exe",
        "Ammyy.exe", "AA_v3.exe"
    },
    "vnc_variants": {
        "winvnc.exe", "winvnc4.exe",
        "tvnserver.exe", "tvnserver_service.exe", 
        "vncserver.exe", "vncviewer.exe",
        "ultravnc.exe",
        "tigervnc.exe",
        "realvnc.exe"
    },
    "windows_native": {
        "mstsc.exe",        
        "msra.exe",         
        "QuickAssist.exe"   
    },
    "browser_extensions": {
        "remoting_host.exe",
        "rdp_host.exe"
    },
    "admin_tools": {
        "psexec.exe", "paexec.exe",
        "screenconnect.client.exe", "screenconnect.service.exe",
        "meshagent.exe"
    },
    "conference_tools": {
        "Zoom.exe",
        "Teams.exe",
        "CiscoWebExStart.exe",
        "webex.exe",
        "Discord.exe"
    }
}
