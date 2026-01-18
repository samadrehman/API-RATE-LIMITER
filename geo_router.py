"""
Geographic Routing System for Load Balancer
Add this as: geo_router.py

WHY: Route users to nearest datacenter for:
- Lower latency (better UX)
- Data residency compliance (GDPR, etc.)
- Better disaster recovery
- Reduced bandwidth costs
"""
import requests
import time
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
import math
from functools import lru_cache

@dataclass
class Datacenter:
    name: str
    region: str  # us-east, eu-west, ap-south, etc.
    country: str
    latitude: float
    longitude: float
    backends: List[str]  # ["http://host:port", ...]
    
    def distance_to(self, lat: float, lon: float) -> float:
        """
        Calculate distance to coordinates using Haversine formula
        Returns distance in kilometers
        """
        R = 6371  # Earth radius in km
        
        lat1, lon1 = math.radians(self.latitude), math.radians(self.longitude)
        lat2, lon2 = math.radians(lat), math.radians(lon)
        
        dlat = lat2 - lat1
        dlon = lon2 - lon1
        
        a = (math.sin(dlat/2)**2 + 
             math.cos(lat1) * math.cos(lat2) * math.sin(dlon/2)**2)
        c = 2 * math.asin(math.sqrt(a))
        
        return R * c


class GeoIPResolver:
    
    def __init__(self, cache_ttl=3600):
        self.cache = {}
        self.cache_ttl = cache_ttl
        
        # Multiple API providers (fallback)
        self.providers = [
            self._resolve_ipapi,
            self._resolve_ipgeolocation,
            self._resolve_ipinfo,
        ]
    
    @lru_cache(maxsize=10000)
    def resolve(self, ip: str) -> Optional[Dict]:
    
        # Skip localhost/private IPs
        if ip in ('127.0.0.1', 'localhost', '::1'):
            return self._get_default_location()
        
        if ip.startswith('192.168.') or ip.startswith('10.'):
            return self._get_default_location()
        
        # Check cache
        cache_key = f"geo:{ip}"
        if cache_key in self.cache:
            cached_data, timestamp = self.cache[cache_key]
            if time.time() - timestamp < self.cache_ttl:
                return cached_data
        
        # Try providers in order
        for provider in self.providers:
            try:
                result = provider(ip)
                if result:
                    # Cache result
                    self.cache[cache_key] = (result, time.time())
                    return result
            except Exception as e:
                print(f"GeoIP provider error: {e}")
                continue
        
        # Fallback to default
        return self._get_default_location()
    
    def _resolve_ipapi(self, ip: str) -> Optional[Dict]:
        url = f"http://ip-api.com/json/{ip}"
        
        response = requests.get(url, timeout=2)
        if response.status_code != 200:
            return None
        
        data = response.json()
        if data.get('status') != 'success':
            return None
        
        return {
            'ip': ip,
            'country': data.get('countryCode'),
            'city': data.get('city'),
            'latitude': data.get('lat'),
            'longitude': data.get('lon'),
            'region': self._determine_region(
                data.get('countryCode'),
                data.get('lat'),
                data.get('lon')
            )
        }
    
    def _resolve_ipgeolocation(self, ip: str) -> Optional[Dict]:
        # Requires API key: https://ipgeolocation.io/
        # For demo, skip this
        return None
    
    def _resolve_ipinfo(self, ip: str) -> Optional[Dict]:
        url = f"https://ipinfo.io/{ip}/json"
        
        response = requests.get(url, timeout=2)
        if response.status_code != 200:
            return None
        
        data = response.json()
        loc = data.get('loc', '0,0').split(',')
        lat, lon = float(loc[0]), float(loc[1])
        
        return {
            'ip': ip,
            'country': data.get('country'),
            'city': data.get('city'),
            'latitude': lat,
            'longitude': lon,
            'region': self._determine_region(data.get('country'), lat, lon)
        }
    
    def _determine_region(self, country: str, lat: float, lon: float) -> str:
   
        # Regional mapping
        region_map = {
            # North America
            'US': self._determine_us_region(lon),
            'CA': 'us-east',
            'MX': 'us-central',
            
            # Europe
            'GB': 'eu-west',
            'FR': 'eu-west',
            'DE': 'eu-central',
            'IT': 'eu-central',
            'ES': 'eu-west',
            'NL': 'eu-west',
            'SE': 'eu-north',
            'NO': 'eu-north',
            'FI': 'eu-north',
            'PL': 'eu-central',
            
            # Asia Pacific
            'IN': 'ap-south',
            'CN': 'ap-northeast',
            'JP': 'ap-northeast',
            'KR': 'ap-northeast',
            'SG': 'ap-southeast',
            'AU': 'ap-southeast',
            'NZ': 'ap-southeast',
            'ID': 'ap-southeast',
            'TH': 'ap-southeast',
            'MY': 'ap-southeast',
            
            # South America
            'BR': 'sa-east',
            'AR': 'sa-east',
            'CL': 'sa-east',
            
            # Africa
            'ZA': 'af-south',
            'NG': 'af-south',
            'EG': 'af-north',
            
            # Middle East
            'AE': 'me-central',
            'SA': 'me-central',
            'IL': 'me-central',
        }
        
        return region_map.get(country, 'us-east')  # Default to us-east
    
    def _determine_us_region(self, lon: float) -> str:
        """Determine US region based on longitude"""
        if lon > -95:
            return 'us-east'
        elif lon < -115:
            return 'us-west'
        else:
            return 'us-central'
    
    def _get_default_location(self) -> Dict:
        """Default location for unknown IPs"""
        return {
            'ip': 'unknown',
            'country': 'US',
            'city': 'Unknown',
            'latitude': 40.7128,
            'longitude': -74.0060,
            'region': 'us-east'
        }


class GeoRouter:

    
    def __init__(self):
        self.datacenters: List[Datacenter] = []
        self.geoip = GeoIPResolver()
        self.fallback_datacenter = None
        
        # Routing stats
        self.stats = {
            'total_routes': 0,
            'routes_by_region': {},
            'avg_distance': 0,
        }
    
    def add_datacenter(self, 
                      name: str,
                      region: str,
                      country: str,
                      latitude: float,
                      longitude: float,
                      backends: List[str]):
        """Add a datacenter to the routing table"""
        dc = Datacenter(
            name=name,
            region=region,
            country=country,
            latitude=latitude,
            longitude=longitude,
            backends=backends
        )
        
        self.datacenters.append(dc)
        
        # Set first as fallback
        if not self.fallback_datacenter:
            self.fallback_datacenter = dc
        
        print(f"✅ Added datacenter: {name} ({region}) - {len(backends)} backends")
    
    def route_request(self, client_ip: str) -> Tuple[Datacenter, float]:
     
        # Resolve IP to location
        location = self.geoip.resolve(client_ip)
        
        if not location or not self.datacenters:
            return self.fallback_datacenter, 0
        
        lat, lon = location['latitude'], location['longitude']
        
        # Find nearest datacenter
        nearest = None
        min_distance = float('inf')
        
        for dc in self.datacenters:
            distance = dc.distance_to(lat, lon)
            
            if distance < min_distance:
                min_distance = distance
                nearest = dc
        
        # Update stats
        self.stats['total_routes'] += 1
        region = nearest.region
        self.stats['routes_by_region'][region] = \
            self.stats['routes_by_region'].get(region, 0) + 1
        
        # Update average distance
        total = self.stats['total_routes']
        self.stats['avg_distance'] = (
            (self.stats['avg_distance'] * (total - 1) + min_distance) / total
        )
        
        return nearest, min_distance
    
    def get_stats(self) -> Dict:
        """Get routing statistics"""
        return {
            'total_routes': self.stats['total_routes'],
            'routes_by_region': self.stats['routes_by_region'],
            'avg_distance_km': round(self.stats['avg_distance'], 2),
            'datacenters': [
                {
                    'name': dc.name,
                    'region': dc.region,
                    'country': dc.country,
                    'backends': len(dc.backends)
                }
                for dc in self.datacenters
            ]
        }



# DEMO SETUP FOR LOCAL TESTING


def setup_demo_geo_routing():
    """
    Demo setup simulating 3 regions
    Uses localhost backends but groups them by 'region'
    """
    router = GeoRouter()
    
    # Simulate US datacenter
    router.add_datacenter(
        name="US-East-Demo",
        region="us-east",
        country="US",
        latitude=37.4316,
        longitude=-78.6569,
        backends=["http://localhost:5001"]
    )
    
    # Simulate EU datacenter
    router.add_datacenter(
        name="EU-West-Demo",
        region="eu-west",
        country="IE",
        latitude=53.3498,
        longitude=-6.2603,
        backends=["http://localhost:5002"]
    )
    
    # Simulate Asia datacenter
    router.add_datacenter(
        name="AP-South-Demo",
        region="ap-south",
        country="IN",
        latitude=19.0760,
        longitude=72.8777,
        backends=["http://localhost:5003"]
    )
    
    return router


# TESTING

if __name__ == '__main__':
    # Test geo routing
    router = setup_demo_geo_routing()
    
    # Test IPs from different regions
    test_ips = {
        'US': '8.8.8.8',          # Google DNS (US)
        'EU': '193.0.6.139',      # RIPE NCC (Netherlands)
        'Asia': '1.1.1.1',        # Cloudflare (Australia)
        'India': '103.21.244.0',  # Example India IP
    }
    
    print("\n" + "="*60)
    print("🌍 Geographic Routing Test")
    print("="*60)
    
    for region, ip in test_ips.items():
        dc, distance = router.route_request(ip)
        print(f"\n{region} IP ({ip}):")
        print(f"  → Routed to: {dc.name}")
        print(f"  → Distance: {distance:.0f} km")
        print(f"  → Backends: {dc.backends}")
    
    # Show stats
    print("\n" + "="*60)
    print("📊 Routing Statistics")
    print("="*60)
    stats = router.get_stats()
    print(f"Total routes: {stats['total_routes']}")
    print(f"Avg distance: {stats['avg_distance_km']} km")
    print(f"\nRoutes by region:")
    for region, count in stats['routes_by_region'].items():
        print(f"  {region}: {count}")