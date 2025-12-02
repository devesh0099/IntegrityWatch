from .base import BaseDetector
from ..core.result import TechniqueResult


class ScreenShareDetector(BaseDetector):
    
    def __init__(self):
        super().__init__(
            name="Screen Sharing Detection",
        )
    
    def scan(self) -> TechniqueResult:
        screen_shares = self.filter_violations(['SCREEN_SHARE_DETECTED'])
        screen_stops = self.filter_violations(['SCREEN_SHARE_STOPPED'])
        
        if not screen_shares:
            return TechniqueResult(
                name=self.name,
                detected=False,
                severity=self.severity,
                details="No screen sharing activity detected",
                count=0
            )
        
        share_count = len(screen_shares)
        stop_count = len(screen_stops)
        
        total_duration = 0.0
        if screen_stops:
            total_duration = self._calculate_duration(screen_shares, screen_stops)
        
        details_parts = [
            f"{share_count} screen sharing incident(s) detected"
        ]
        
        if total_duration > 0:
            details_parts.append(f"Total duration: {total_duration:.1f} seconds")
        
        if share_count > stop_count:
            details_parts.append(f"WARNING: {share_count - stop_count} session(s) not stopped properly")
        
        urls = set()
        for violation in screen_shares:
            url = violation.get('details', {}).get('url')
            if url:
                urls.add(url)
        
        if urls:
            url_list = list(urls)[:3]
            details_parts.append(f"URLs: {', '.join(url_list)}")
        
        return TechniqueResult(
            name=self.name,
            detected=True,
            severity=self.severity,
            details=" | ".join(details_parts),
            count=share_count
        )
    
    def _calculate_duration(self, shares: list, stops: list) -> float:
        if not shares or not stops:
            return 0.0
        
        total_seconds = 0.0
        
        for share in shares:
            share_time = share.get('timestamp', 0)
            
            for stop in stops:
                stop_time = stop.get('timestamp', 0)
                if stop_time > share_time:
                    duration = (stop_time - share_time) / 1000
                    total_seconds += duration
                    break
        
        return total_seconds
