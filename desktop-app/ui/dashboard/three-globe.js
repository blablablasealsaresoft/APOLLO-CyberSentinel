// EMERGENCY FIX - Stable Earth Globe Without Infinite Loops
async function initializeThreeJSGlobe() {
    const container = document.getElementById('globe-wrapper');
    if (!container) {
        console.error('❌ Globe container not found');
        return;
    }

    console.log('🌍 Initializing stable Earth globe...');

    // Remove existing canvas
    const existingCanvas = container.querySelector('canvas');
    if (existingCanvas) existingCanvas.remove();

    // Scene setup
    const scene = new THREE.Scene();
    scene.background = new THREE.Color(0x000011);

    const width = container.clientWidth || 800;
    const height = container.clientHeight || 600;

    const camera = new THREE.PerspectiveCamera(45, width / height, 0.1, 1000);
    camera.position.set(0, 0, 2.5);

    const renderer = new THREE.WebGLRenderer({ antialias: true });
    renderer.setSize(width, height);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    container.appendChild(renderer.domElement);

    // Simple lighting
    const ambientLight = new THREE.AmbientLight(0x404040, 0.4);
    scene.add(ambientLight);

    const directionalLight = new THREE.DirectionalLight(0xffffff, 1);
    directionalLight.position.set(1, 1, 1);
    scene.add(directionalLight);

    // Earth group
    const earthGroup = new THREE.Group();
    scene.add(earthGroup);

    // Create simple but stable Earth
    const earthGeometry = new THREE.SphereGeometry(1, 64, 32);
    
    // Load only the main diffuse texture to avoid complex material issues
    const textureLoader = new THREE.TextureLoader();
    const earthTexture = textureLoader.load('../../assets/Earth2k/Textures/Diffuse_2K.png', 
        (texture) => {
            console.log('✅ Earth texture loaded successfully');
            texture.wrapS = THREE.RepeatWrapping;
            texture.wrapT = THREE.RepeatWrapping;
        },
        undefined,
        (error) => {
            console.error('❌ Failed to load Earth texture:', error);
        }
    );

    // Simple, stable material
    const earthMaterial = new THREE.MeshLambertMaterial({
        map: earthTexture,
        color: 0xffffff
    });

    const earthMesh = new THREE.Mesh(earthGeometry, earthMaterial);
    earthGroup.add(earthMesh);

    // Add REAL threat indicators from backend
    let threatIndicators = [];
    try {
        console.log('🔍 Loading REAL threat data...');
        const realThreats = await window.electronAPI.getThreatIntelligence();
        console.log('✅ Loaded threats:', realThreats.length);

        // Country coordinates
        const countryCoords = {
            'United States': [39.8283, -98.5795],
            'Russia': [61.5240, 105.3188], 
            'China': [35.8617, 104.1954],
            'Ukraine': [48.3794, 31.1656],
            'Germany': [51.1657, 10.4515],
            'France': [46.2276, 2.2137],
            'United Kingdom': [55.3781, -3.4360],
            'Japan': [36.2048, 138.2529],
            'Global': [0, 0],
            'Unknown': [0, 0]
        };

        realThreats.slice(0, 8).forEach((threat) => {
            const coords = countryCoords[threat.location] || [0, 0];
            const lat = coords[0] * Math.PI / 180;
            const lon = coords[1] * Math.PI / 180;

            const x = Math.cos(lat) * Math.sin(lon);
            const y = Math.sin(lat);
            const z = Math.cos(lat) * Math.cos(lon);

            const threatGeometry = new THREE.SphereGeometry(0.03, 8, 8);
            const threatColor = threat.severity === 'critical' ? 0xff0000 :
                              threat.severity === 'high' ? 0xff9800 : 0x2196f3;

            const threatMaterial = new THREE.MeshBasicMaterial({
                color: threatColor
            });

            const threatMesh = new THREE.Mesh(threatGeometry, threatMaterial);
            threatMesh.position.set(x * 1.1, y * 1.1, z * 1.1);

            threatIndicators.push({
                mesh: threatMesh,
                severity: threat.severity,
                originalScale: 1
            });

            earthGroup.add(threatMesh);
            console.log(`✅ Added threat: ${threat.title || 'Unknown'} at ${threat.location}`);
        });

    } catch (error) {
        console.error('❌ Failed to load threat data:', error);
    }

    // Simple orbit controls
    let controls;
    try {
        if (typeof THREE.OrbitControls !== 'undefined') {
            controls = new THREE.OrbitControls(camera, renderer.domElement);
            controls.enableDamping = true;
            controls.dampingFactor = 0.1;
            controls.minDistance = 1.5;
            controls.maxDistance = 4;
        }
    } catch (e) {
        console.log('⚠️ OrbitControls not available');
    }

    // STABLE animation loop with error handling
    let animationId;
    let isAnimating = false;

    function animate() {
        if (isAnimating) return; // Prevent multiple animation loops
        isAnimating = true;

        try {
            animationId = requestAnimationFrame(() => {
                isAnimating = false;
                animate();
            });

            // Simple Earth rotation
            earthGroup.rotation.y += 0.002;

            // Simple threat pulsing without complex materials
            const time = Date.now() * 0.001;
            threatIndicators.forEach((indicator, index) => {
                if (indicator.mesh && indicator.mesh.scale) {
                    const pulse = Math.sin(time * 2 + index) * 0.2 + 1;
                    indicator.mesh.scale.setScalar(pulse);
                }
            });

            if (controls) controls.update();
            renderer.render(scene, camera);

        } catch (renderError) {
            console.error('❌ Render error caught:', renderError);
            isAnimating = false;
            // Stop animation on error
            if (animationId) {
                cancelAnimationFrame(animationId);
            }
        }
    }

    // Start animation with error protection
    try {
        animate();
        console.log('✅ Stable Earth globe initialized successfully');
    } catch (error) {
        console.error('❌ Animation failed to start:', error);
    }

    // Cleanup function
    window.cleanupGlobe = function() {
        if (animationId) {
            cancelAnimationFrame(animationId);
        }
        isAnimating = false;
        console.log('🧹 Globe animation stopped');
    };

    // Resize handler
    window.addEventListener('resize', () => {
        try {
            camera.aspect = container.clientWidth / container.clientHeight;
            camera.updateProjectionMatrix();
            renderer.setSize(container.clientWidth, container.clientHeight);
        } catch (resizeError) {
            console.error('❌ Resize error:', resizeError);
        }
    });
}

// Export
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { initializeThreeJSGlobe };
}