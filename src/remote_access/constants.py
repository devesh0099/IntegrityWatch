# All suspicious ports
SUSPICIOUS_PORTS = {
    3389, # RDP - Microsoft standard
    5900, # VNC - IETF RFC 6143
    5901, 5902, 5903, 5904, 5905, # VNC additional displays
    5938, # TeamViewer - Official docs
    6568, # AnyDesk - Official docs
    7070, # AnyDesk direct connection
    21116, 21117, 21118, 21119, # RustDesk
    11011, 11012 # Supremo
}

COMMON_FALLBACK_PORTS ={
    80, # HTTP
    443, # HTTPS
    8080, 8443 # HTTP alternatives
}

COMMON_LEGITIMATE_PORTS = {
    20, 21, # FTP
    22, # SSH
    25, # SMTP
    53, # DNS
    110, # POP3
    143, # IMAP
    465, 587, # SMTP SSL
    993, 995, # IMAP/POP3 SSL
    3306, # MySQL
    5432, # PostgreSQL
}
    

# Known remote access domains
KNOWN_REMOTE_ACCESS_DOMAINS = [
    'teamviewer.com',
    'anydesk.com',
    'net.anydesk.com',
    'realvnc.com',
    'tightvnc.com',
    'rustdesk.com',
]

# Port to tool mapping {Out of all suspicious ports only these ones are 100% certain to a specific tool}
PORT_TO_TOOL = {
    3389: 'RDP',
    5900: 'VNC',
    5938: 'TeamViewer',
    6568: 'AnyDesk',
}

# PROCESS BLOCKLIST (Cross-Platform)
PROCESS_BLOCKLIST = {    
    "commercial_tools": {

        "TeamViewer.exe",         
        "TeamViewer_Service.exe", 
        "tv_w32.exe",            
        "tv_x64.exe",            
        "teamviewer",            
        "teamviewerd",           
        "TeamViewer",            
        "TeamViewerHost",        

        "AnyDesk.exe",           
        "ad.exe",                
        "anydesk",               
        "AnyDesk",               
        
        "LogMeIn.exe",           
        "LogMeInSystray.exe",    
        "LMIGuardian.exe",       
        "logmein",               
        "LogMeIn",               
        
        "GoToMeeting.exe",       
        "g2mcomm.exe",           
        "g2mstart.exe",          
        "g2mlauncher.exe",       
        
        "Splashtop.exe",         
        "SRServer.exe",          
        "SRService.exe",         
        "SRFeature.exe",         
        "Splashtop Business",    
        "Splashtop Streamer",    

        "Supremo.exe",           
        "SupremoService.exe",    
        "SupremoHelper.exe",     
        
        "RustDesk.exe",          
        "rustdesk",              
        "RustDesk",              
        
        "AeroAdmin.exe",         
        "aeroadmin",             
        
        "Ammyy.exe",             
        "AA_v3.exe",             

        "UltraViewer.exe",       
        "UltraViewer_Service.exe",
        "UltraViewer_Desktop.exe",
        
        "RemotePC.exe",          
        "rpcservice.exe",        
        "RemotePCDesktop.exe",   
        
        "ZohoAssist.exe",        
        "ZohoAssistService.exe", 
        
        "dwagent.exe",           
        "dwagent",               
        
        "chrome_remote_desktop", 
    },

    "vnc_variants": {
        "winvnc.exe",            
        "winvnc4.exe",           
        "tvnserver.exe",         
        "tvnserver_service.exe", 
        "vncserver.exe",         
        "vncviewer.exe",         
        "ultravnc.exe",          
        "tigervnc.exe",          
        "realvnc.exe",           
        "vncserver_x64.exe",     

        "Xvnc",                  
        "vncserver",             
        "x11vnc",                
        "tightvncserver",        
        "vino",                  
        "vino-server",           
        "tigervnc",              
        "krfb",                  
        
        "ScreensharingAgent",    
    },

    "windows_native": {
        "mstsc.exe",             
        "msra.exe",              
        "QuickAssist.exe",       
    },

    "browser_extensions": {

        "remoting_host.exe",     
        "chrome-remote-desktop", 
        "Chrome Remote Desktop", 
        
        "rdp_host.exe",          
    },

    "admin_tools": {
        "psexec.exe",            
        "psexec64.exe",          
        "paexec.exe",            
        
        "screenconnect.client.exe",   
        "screenconnect.service.exe",  
        "ScreenConnect.ClientService",
        "screenconnect",              
        
        "meshagent.exe",         
        "meshagent",             
        "MeshAgent",             
        
        "rutserv.exe",           
        "rfusclient.exe",        
        "Agent.exe",             
        
        "ITSMService.exe",       
        "RmmService.exe",        
    },

    "screen_recording": {

        "obs64.exe",             
        "obs32.exe",             
        "obs.exe",               
        "obs",                   
        
        "ShareX.exe",            

        "bdcam.exe",             
        "bdcam_nonadmin.exe",    
        "bandicam.exe",          

        "CamtasiaStudio.exe",    
        "Camtasia.exe",          
        "Camtasia 2023",         
        "Camtasia 2024",         
        "camtasia",              
        
        "ScreenFlow",            

        "Snagit.exe",            
        "SnagitEditor.exe",      
        "Snagit 2023",           
        "Snagit 2024",           
        
        "ScreenToGif.exe",       

        "Loom.exe",              
        "loom",                  
        "Loom",                  
        
        "screen_recorder.exe",   
        "IcecreamScreenRecorder.exe",
        
        "screenrec.exe",         
        "screenrec",             
        "ScreenRec",             
        
        "simplescreenrecorder",  
        "ssr-glinject",          
        
        "kazam",                 
        
        "recordmydesktop",       
        "gtk-recordmydesktop",   
        "qt-recordmydesktop",    
        
        "peek",                  

        "vokoscreen",            
        "vokoscreenNG",          

        "green-recorder",        

        "QuickTime Player",      
        
        "Kap",                   
        
        "ffmpeg.exe",            
        "ffmpeg",                
    },

    "virtual_camera": {
        "obs-virtualcam.exe",    
        "obs-camera",            

        "ManyCam.exe",           
        "ManyCamService.exe",    
        "ManyCam",               

        "VCam.exe",              
        "XSplitVCam.exe",        

        "Snap Camera.exe",       
        "Snap Camera",           

        "CamTwist",              
        "CamTwist Studio",       
        
        "SplitCam.exe",          

        "WebcamMax.exe",         
        
        "SparkoCam.exe",         

        "webcamoid.exe",         
        "webcamoid",             
        
        "ChromaCam.exe",         

        "YouCam.exe",            
        "YouCamService.exe",     

        "AlterCam.exe",          
        
        "LogiCapture.exe",       
        "Logitech Capture",      
    },

    "streaming_software": {
        "Streamlabs OBS.exe",    
        "Streamlabs Desktop.exe",
        "Streamlabs OBS",        
        
        "XSplit.Core.exe",       
        "XSplitBroadcaster.exe", 

        "Restream Studio.exe",   
        "Restream Studio",      

        "TwitchStudio.exe",        
        "Twitch Studio",          
        "twitch-studio",  

        "StreamYard.exe",        
        
        "vMix64.exe",            
        "vMix.exe",              
        
        "Wirecast.exe",          
        "Wirecast",              
    },

    "conference_tools_sharing": {
        "Zoom.exe",              
        "zoom",                  
        "zoom.us",               
        "CptHost.exe",           
        
        "Teams.exe",             
        "teams",                 
        "Microsoft Teams",       
        "ms-teams",              
        
        "CiscoWebExStart.exe",   
        "webex.exe",             
        "WebexHost.exe",         
        "Webex",                 
        "CiscoCollabHost",       
        "webexmta",              

        "Discord.exe",           
        "discord",               
        "Discord",               
        
        "slack.exe",             
        "slack",                 
        "Slack",                 
        
        "Skype.exe",             
        "skypeforlinux",         
        "Skype",                 

        "jitsi-meet.exe",        
        "jitsi-meet",            
        "Jitsi Meet",            
        
        "BlueJeans.exe",         
        "BlueJeans",             
    },
}