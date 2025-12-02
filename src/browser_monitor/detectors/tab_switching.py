from collections import Counter
from .base import BaseDetector
from ..core.result import TechniqueResult

class TabSwitchingDetector(BaseDetector):
    
    URL_CATEGORIES = {
        'communication': [
            'meet.google.com', 'teams.microsoft.com', 'zoom.us',
            'discord.com', 'slack.com', 'whatsapp.com', 'telegram.org',
            'messenger.com', 'chat.google.com', 'hangouts.google.com'
        ],
        'search': [
            'google.com/search', 'bing.com/search', 'duckduckgo.com'
        ],
        'social': [
            'facebook.com', 'twitter.com', 'instagram.com', 'reddit.com'
        ]
    }
    
    def __init__(self):
        super().__init__(
            name="Tab Switching Detection"
        )
    
    def scan(self) -> TechniqueResult:
        tab_violations = self.filter_violations([
            'SUSPICIOUS_TAB_ACTIVATED',
            'SUSPICIOUS_TAB_ALREADY_OPEN',
            'SUSPICIOUS_TAB_NAVIGATION'
        ])
        
        if not tab_violations:
            return TechniqueResult(
                name=self.name,
                detected=False,
                severity=self.severity,
                details="No suspicious tab activity detected",
                count=0
            )
        
        categories = self._categorize_violations(tab_violations)
        total_count = len(tab_violations)
        
        rapid_switching = self._detect_rapid_switching(tab_violations)
        
        details_parts = [
            f"{total_count} suspicious tab event(s)"
        ]
        
        if categories:
            category_str = ", ".join([f"{cat}: {count}" for cat, count in categories.items()])
            details_parts.append(f"Categories: {category_str}")
        
        if rapid_switching:
            details_parts.append(f"ALERT: Rapid tab switching detected ({rapid_switching} switches/min)")
        
        return TechniqueResult(
            name=self.name,
            detected=True,
            severity=self.severity,
            details=" | ".join(details_parts),
            count=total_count
        )
    
    def _categorize_violations(self, violations: list[dict]) -> dict[str, int]:
        categories = Counter()
        
        for violation in violations:
            url = violation.get('details', {}).get('url', '')
            category = self._categorize_url(url)
            categories[category] += 1
        
        return dict(categories)
    
    def _categorize_url(self, url: str) -> str:
        url_lower = url.lower()
        
        for category, patterns in self.URL_CATEGORIES.items():
            for pattern in patterns:
                if pattern in url_lower:
                    return category
        
        return 'other'
    
    def _detect_rapid_switching(self, violations: list[dict]) -> int:
        if len(violations) < 5:
            return 0
        
        sorted_violations = sorted(violations, key=lambda x: x.get('timestamp', 0))
        
        max_switches = 0
        
        for i in range(len(sorted_violations) - 4):
            window_start = sorted_violations[i].get('timestamp', 0)
            window_end = sorted_violations[i + 4].get('timestamp', 0)
            
            time_diff = (window_end - window_start) / 1000
            
            if time_diff <= 60:
                switches_in_window = sum(
                    1 for v in sorted_violations
                    if window_start <= v.get('timestamp', 0) <= window_end
                )
                max_switches = max(max_switches, switches_in_window)
        
        return max_switches if max_switches >= 5 else 0
