/**
 * RateLimiter SDK
 * Client-side rate limiting and API protection
 * 
 * Usage:
 * <script src="https://your-domain.com/sdk.js"></script>
 * <script>
 *   RateLimiter.init({
 *     apiKey: 'your_api_key_here',
 *     backendUrl: 'https://your-domain.com',
 *     showWidget: true
 *   });
 * </script>
 */

(function(window) {
    'use strict';

    const RateLimiter = {
        config: {
            apiKey: null,
            backendUrl: null,
            showWidget: false,
            position: 'bottom-right',
            checkBeforeRequest: true
        },

        stats: {
            remaining: 100,
            limit: 100,
            tier: 'free',
            resetAt: null
        },

        /**
         * Initialize the SDK
         */
        init: function(options) {
            // Merge config
            this.config = Object.assign({}, this.config, options);

            if (!this.config.apiKey) {
                console.error('[RateLimiter] API key is required');
                return;
            }

            if (!this.config.backendUrl) {
                console.error('[RateLimiter] Backend URL is required');
                return;
            }

            console.log('[RateLimiter] Initialized with API key:', this.config.apiKey.substring(0, 8) + '...');

            // Intercept fetch requests
            this.interceptFetch();

            // Intercept XMLHttpRequest
            this.interceptXHR();

            // Show widget if enabled
            if (this.config.showWidget) {
                this.createWidget();
            }

            // Fetch initial stats
            this.fetchStats();
        },

        /**
         * Intercept native fetch
         */
        interceptFetch: function() {
            const self = this;
            const originalFetch = window.fetch;

            window.fetch = async function(...args) {
                // Check rate limit before making request
                if (self.config.checkBeforeRequest) {
                    const allowed = await self.checkRateLimit();
                    
                    if (!allowed) {
                        self.showRateLimitError();
                        throw new Error('Rate limit exceeded');
                    }
                }

                // Proceed with original fetch
                const startTime = Date.now();
                try {
                    const response = await originalFetch(...args);
                    const endTime = Date.now();

                    // Track the request
                    self.trackRequest(args[0], 'GET', response.status, endTime - startTime);

                    return response;
                } catch (error) {
                    const endTime = Date.now();
                    self.trackRequest(args[0], 'GET', 0, endTime - startTime);
                    throw error;
                }
            };
        },

        /**
         * Intercept XMLHttpRequest
         */
        interceptXHR: function() {
            const self = this;
            const originalOpen = XMLHttpRequest.prototype.open;
            const originalSend = XMLHttpRequest.prototype.send;

            XMLHttpRequest.prototype.open = function(method, url, ...args) {
                this._method = method;
                this._url = url;
                this._startTime = Date.now();
                return originalOpen.call(this, method, url, ...args);
            };

            XMLHttpRequest.prototype.send = async function(...args) {
                if (self.config.checkBeforeRequest) {
                    const allowed = await self.checkRateLimit();
                    
                    if (!allowed) {
                        self.showRateLimitError();
                        throw new Error('Rate limit exceeded');
                    }
                }

                this.addEventListener('load', function() {
                    const endTime = Date.now();
                    self.trackRequest(this._url, this._method, this.status, endTime - this._startTime);
                });

                return originalSend.call(this, ...args);
            };
        },

        /**
         * Check rate limit with backend
         */
        checkRateLimit: async function() {
            try {
                const response = await fetch(this.config.backendUrl + '/sdk/check', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        api_key: this.config.apiKey,
                        endpoint: window.location.pathname,
                        method: 'GET'
                    })
                });

                const data = await response.json();

                // Update stats
                this.stats.remaining = data.remaining || 0;
                this.stats.limit = data.limit || 100;
                this.stats.tier = data.tier || 'free';
                this.stats.resetAt = data.reset_at;

                // Update widget
                this.updateWidget();

                return data.allowed;
            } catch (error) {
                console.error('[RateLimiter] Error checking rate limit:', error);
                // On error, allow the request (fail open)
                return true;
            }
        },

        /**
         * Track request with backend
         */
        trackRequest: function(endpoint, method, statusCode, responseTime) {
            // Fire and forget - don't block on this
            fetch(this.config.backendUrl + '/sdk/track', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    api_key: this.config.apiKey,
                    endpoint: endpoint,
                    method: method,
                    status_code: statusCode,
                    response_time_ms: responseTime
                })
            }).catch(err => {
                console.error('[RateLimiter] Error tracking request:', err);
            });
        },

        /**
         * Fetch current stats
         */
        fetchStats: async function() {
            try {
                const response = await fetch(this.config.backendUrl + '/usage?api_key=' + this.config.apiKey);
                const data = await response.json();

                if (data) {
                    this.stats.remaining = data.remaining || data.requests_remaining || 0;
                    this.stats.limit = data.limit || 100;
                    this.stats.tier = data.tier || 'free';
                    this.updateWidget();
                }
            } catch (error) {
                console.error('[RateLimiter] Error fetching stats:', error);
            }
        },

        /**
         * Create usage widget
         */
        createWidget: function() {
            const widget = document.createElement('div');
            widget.id = 'ratelimiter-widget';
            widget.innerHTML = `
                <div style="
                    position: fixed;
                    ${this.config.position.includes('bottom') ? 'bottom: 20px;' : 'top: 20px;'}
                    ${this.config.position.includes('right') ? 'right: 20px;' : 'left: 20px;'}
                    background: white;
                    border: 2px solid #667eea;
                    border-radius: 12px;
                    padding: 16px;
                    box-shadow: 0 4px 20px rgba(0,0,0,0.15);
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
                    font-size: 14px;
                    z-index: 999999;
                    min-width: 200px;
                ">
                    <div style="font-weight: 600; margin-bottom: 8px; color: #1a1a1a;">
                        🔒 API Usage
                    </div>
                    <div id="rl-stats" style="color: #666; margin-bottom: 8px;">
                        <span id="rl-remaining">--</span>/<span id="rl-limit">--</span> requests
                    </div>
                    <div style="
                        height: 6px;
                        background: #e5e7eb;
                        border-radius: 3px;
                        overflow: hidden;
                        margin-bottom: 8px;
                    ">
                        <div id="rl-progress" style="
                            height: 100%;
                            background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
                            transition: width 0.3s ease;
                            width: 0%;
                        "></div>
                    </div>
                    <div style="font-size: 11px; color: #888;">
                        Tier: <span id="rl-tier" style="font-weight: 600;">--</span>
                    </div>
                </div>
            `;
            document.body.appendChild(widget);
        },

        /**
         * Update widget with current stats
         */
        updateWidget: function() {
            const remainingEl = document.getElementById('rl-remaining');
            const limitEl = document.getElementById('rl-limit');
            const progressEl = document.getElementById('rl-progress');
            const tierEl = document.getElementById('rl-tier');

            if (remainingEl) remainingEl.textContent = this.stats.remaining;
            if (limitEl) limitEl.textContent = this.stats.limit;
            if (tierEl) tierEl.textContent = this.stats.tier;

            if (progressEl) {
                const used = this.stats.limit - this.stats.remaining;
                const percentage = (used / this.stats.limit) * 100;
                progressEl.style.width = percentage + '%';

                // Change color based on usage
                if (percentage > 90) {
                    progressEl.style.background = 'linear-gradient(90deg, #ef4444 0%, #dc2626 100%)';
                } else if (percentage > 75) {
                    progressEl.style.background = 'linear-gradient(90deg, #f59e0b 0%, #d97706 100%)';
                } else {
                    progressEl.style.background = 'linear-gradient(90deg, #667eea 0%, #764ba2 100%)';
                }
            }
        },

        /**
         * Show rate limit error
         */
        showRateLimitError: function() {
            // Create modal overlay
            const modal = document.createElement('div');
            modal.innerHTML = `
                <div style="
                    position: fixed;
                    top: 0;
                    left: 0;
                    right: 0;
                    bottom: 0;
                    background: rgba(0,0,0,0.5);
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    z-index: 9999999;
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
                " id="rl-modal">
                    <div style="
                        background: white;
                        border-radius: 16px;
                        padding: 32px;
                        max-width: 400px;
                        text-align: center;
                        box-shadow: 0 20px 60px rgba(0,0,0,0.3);
                    ">
                        <div style="font-size: 48px; margin-bottom: 16px;">⚠️</div>
                        <h2 style="margin: 0 0 12px 0; color: #1a1a1a;">Rate Limit Reached</h2>
                        <p style="color: #666; margin: 0 0 24px 0;">
                            You've used all ${this.stats.limit} requests on the ${this.stats.tier} plan.
                        </p>
                        <button onclick="document.getElementById('rl-modal').remove()" style="
                            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                            color: white;
                            border: none;
                            padding: 12px 24px;
                            border-radius: 8px;
                            cursor: pointer;
                            font-size: 14px;
                            font-weight: 600;
                        ">
                            OK
                        </button>
                    </div>
                </div>
            `;
            document.body.appendChild(modal);

            // Auto-remove after 5 seconds
            setTimeout(() => {
                const modalEl = document.getElementById('rl-modal');
                if (modalEl) modalEl.remove();
            }, 5000);
        }
    };

    // Expose to window
    window.RateLimiter = RateLimiter;

})(window);