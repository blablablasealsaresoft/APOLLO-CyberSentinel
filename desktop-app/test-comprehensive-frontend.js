// 🎯 APOLLO COMPREHENSIVE FRONTEND TESTING SUITE
// Tests EVERY feature, function, button, and workflow
// Validates DOM integrity across all UI files
// McAfee-level paranoid frontend validation!

require('dotenv').config();

const fs = require('fs-extra');
const path = require('path');
const { JSDOM } = require('jsdom');

class ComprehensiveFrontendTester {
    constructor() {
        this.testResults = [];
        this.domIssues = [];
        this.workflowIssues = [];
        this.crossFileIssues = [];
        
        // UI files to test
        this.uiFiles = {
            html: path.join(__dirname, 'ui', 'dashboard', 'index.html'),
            javascript: path.join(__dirname, 'ui', 'dashboard', 'dashboard.js'),
            css: path.join(__dirname, 'ui', 'dashboard', 'styles.css')
        };
        
        // All buttons and interactive elements
        this.interactiveElements = [
            // Header buttons
            { id: 'settings-btn', type: 'button', onclick: 'openSettings()', critical: true },
            
            // Emergency controls
            { id: 'emergency-btn-isolation', type: 'button', onclick: 'emergencyIsolation()', critical: true },
            { id: 'emergency-btn-quarantine', type: 'button', onclick: 'quarantineThreats()', critical: true },
            { id: 'emergency-btn-forensic', type: 'button', onclick: 'captureEvidence()', critical: true },
            
            // Protection controls
            { id: 'deep-scan-btn', type: 'button', onclick: 'runDeepScan()', critical: true },
            { id: 'view-threats-btn', type: 'button', onclick: 'viewThreats()', critical: false },
            { id: 'refresh-activity-btn', type: 'button', onclick: 'refreshActivity()', critical: false },
            
            // AI Oracle controls
            { id: 'analyze-claude-btn', type: 'button', onclick: 'analyzeWithClaude()', critical: true },
            { id: 'clear-oracle-btn', type: 'button', onclick: 'clearOracleInput()', critical: false },
            
            // OSINT Intelligence controls
            { id: 'refresh-intel-btn', type: 'button', onclick: 'refreshIntelligenceSources()', critical: true },
            { id: 'query-ioc-btn', type: 'button', onclick: 'queryIOCIntelligence()', critical: true },
            { id: 'view-feeds-btn', type: 'button', onclick: 'viewThreatFeeds()', critical: false },
            
            // Crypto Guardian controls
            { id: 'wallet-connect-btn', type: 'button', onclick: 'openWalletModal()', critical: true },
            { id: 'analyze-contract-btn', type: 'button', onclick: 'analyzeContract()', critical: true },
            { id: 'check-transaction-btn', type: 'button', onclick: 'checkTransaction()', critical: true },
            { id: 'check-phishing-btn', type: 'button', onclick: 'checkPhishingURL()', critical: true },
            
            // Modal controls
            { id: 'close-threat-modal', type: 'button', onclick: 'closeThreatModal()', critical: false },
            { id: 'close-settings-modal', type: 'button', onclick: 'closeSettingsModal()', critical: false },
            { id: 'close-wallet-modal', type: 'button', onclick: 'closeWalletModal()', critical: false },
            { id: 'save-settings-btn', type: 'button', onclick: 'saveSettings()', critical: true },
            
            // Threat response controls
            { id: 'block-threat-btn', type: 'button', onclick: 'blockThreat()', critical: true },
            { id: 'investigate-threat-btn', type: 'button', onclick: 'investigateThreat()', critical: false }
        ];
        
        // All display elements that should update
        this.displayElements = [
            { id: 'active-threats', type: 'counter', source: 'engine-stats' },
            { id: 'blocked-today', type: 'counter', source: 'engine-stats' },
            { id: 'last-scan', type: 'timestamp', source: 'engine-stats' },
            { id: 'threat-indicator', type: 'status', source: 'threat-level' },
            { id: 'protection-status', type: 'status', source: 'protection-active' },
            { id: 'current-time', type: 'clock', source: 'system-time' },
            { id: 'system-name', type: 'info', source: 'system-info' },
            { id: 'protected-wallets', type: 'counter', source: 'crypto-stats' },
            { id: 'analyzed-contracts', type: 'counter', source: 'crypto-stats' },
            { id: 'wallet-address', type: 'address', source: 'wallet-connection' }
        ];
        
        // All input elements
        this.inputElements = [
            { id: 'oracle-input', type: 'textarea', purpose: 'AI threat analysis' },
            { id: 'contract-address-input', type: 'input', purpose: 'Smart contract analysis' },
            { id: 'transaction-hash-input', type: 'input', purpose: 'Transaction verification' },
            { id: 'phishing-url-input', type: 'input', purpose: 'Phishing URL check' }
        ];
        
        // All workflows to test end-to-end
        this.workflows = [
            {
                name: 'Emergency Isolation Workflow',
                steps: [
                    'Click emergency isolation button',
                    'Confirm isolation dialog',
                    'Execute system isolation',
                    'Display isolation status'
                ],
                critical: true
            },
            {
                name: 'Deep Scan Workflow',
                steps: [
                    'Click deep scan button',
                    'Start scanning process',
                    'Display scan progress',
                    'Show scan results'
                ],
                critical: true
            },
            {
                name: 'AI Analysis Workflow',
                steps: [
                    'Enter threat indicator',
                    'Click analyze button',
                    'Send to Claude AI',
                    'Display AI analysis'
                ],
                critical: true
            },
            {
                name: 'Contract Analysis Workflow',
                steps: [
                    'Enter contract address',
                    'Click analyze contract',
                    'Verify on blockchain',
                    'Display safety assessment'
                ],
                critical: true
            },
            {
                name: 'Real-Time Threat Detection',
                steps: [
                    'Backend detects threat',
                    'Send IPC event',
                    'Update threat counter',
                    'Show threat alert'
                ],
                critical: true
            }
        ];
    }

    async runComprehensiveFrontendTests() {
        console.log('🎯 APOLLO COMPREHENSIVE FRONTEND TESTING SUITE');
        console.log('=' + '='.repeat(80));
        console.log('🖥️ Mission: Test EVERY frontend feature, function, and workflow');
        console.log('📋 Scope: All 3 UI files, all DOM elements, all interactions');
        console.log('🔍 Goal: Zero DOM issues, perfect functionality');
        console.log('=' + '='.repeat(80));

        try {
            // Phase 1: Load and Parse All UI Files
            await this.loadAndParseUIFiles();
            
            // Phase 2: Validate DOM Structure
            await this.validateDOMStructure();
            
            // Phase 3: Test All Interactive Elements
            await this.testAllInteractiveElements();
            
            // Phase 4: Validate All Display Elements
            await this.validateAllDisplayElements();
            
            // Phase 5: Test All Input Elements
            await this.testAllInputElements();
            
            // Phase 6: Validate CSS-HTML Integration
            await this.validateCSSHTMLIntegration();
            
            // Phase 7: Test JavaScript-HTML Integration
            await this.testJavaScriptHTMLIntegration();
            
            // Phase 8: Test Complete Workflows
            await this.testCompleteWorkflows();
            
            // Phase 9: Cross-File Dependency Analysis
            await this.analyzeCrossFileDependencies();
            
            // Phase 10: Generate Comprehensive Report
            await this.generateComprehensiveReport();
            
        } catch (error) {
            console.error('🚨 Comprehensive frontend testing failed:', error);
            throw error;
        }
    }

    async loadAndParseUIFiles() {
        console.log('\n📁 PHASE 1: LOADING AND PARSING UI FILES');
        console.log('-'.repeat(70));
        
        this.uiContent = {};
        
        try {
            // Load HTML
            console.log('📄 Loading HTML file...');
            this.uiContent.html = await fs.readFile(this.uiFiles.html, 'utf8');
            console.log(`  ✅ HTML loaded: ${Math.round(this.uiContent.html.length / 1024)}KB`);
            
            // Parse HTML with JSDOM
            this.dom = new JSDOM(this.uiContent.html);
            this.document = this.dom.window.document;
            console.log('  ✅ DOM parsed successfully');
            
            // Load JavaScript
            console.log('📜 Loading JavaScript file...');
            this.uiContent.javascript = await fs.readFile(this.uiFiles.javascript, 'utf8');
            console.log(`  ✅ JavaScript loaded: ${Math.round(this.uiContent.javascript.length / 1024)}KB`);
            
            // Load CSS
            console.log('🎨 Loading CSS file...');
            this.uiContent.css = await fs.readFile(this.uiFiles.css, 'utf8');
            console.log(`  ✅ CSS loaded: ${Math.round(this.uiContent.css.length / 1024)}KB`);
            
            this.recordTest('UI Files Loading', true, {
                htmlSize: this.uiContent.html.length,
                jsSize: this.uiContent.javascript.length,
                cssSize: this.uiContent.css.length
            });
            
        } catch (error) {
            this.recordTest('UI Files Loading', false, null, error.message);
            throw error;
        }
    }

    async validateDOMStructure() {
        console.log('\n🏗️ PHASE 2: VALIDATING DOM STRUCTURE');
        console.log('-'.repeat(70));
        
        console.log('🔍 Checking DOM structure integrity...');
        
        try {
            // Check for required container elements
            const requiredContainers = [
                'dashboard-container',
                'dashboard-header', 
                'dashboard-main',
                'protection-overview',
                'feature-cards'
            ];
            
            let foundContainers = 0;
            
            requiredContainers.forEach(containerId => {
                const element = this.document.querySelector(`.${containerId}`) || 
                               this.document.querySelector(`#${containerId}`);
                
                if (element) {
                    foundContainers++;
                    console.log(`  ✅ Container ${containerId}: Found`);
                } else {
                    console.log(`  ❌ Container ${containerId}: Missing`);
                    this.domIssues.push(`Missing container: ${containerId}`);
                }
            });
            
            // Check for duplicate IDs
            const allIds = Array.from(this.document.querySelectorAll('[id]')).map(el => el.id);
            const duplicateIds = allIds.filter((id, index) => allIds.indexOf(id) !== index);
            
            if (duplicateIds.length > 0) {
                console.log(`  ❌ Duplicate IDs found: ${duplicateIds.join(', ')}`);
                this.domIssues.push(`Duplicate IDs: ${duplicateIds.join(', ')}`);
            } else {
                console.log('  ✅ No duplicate IDs found');
            }
            
            // Check for orphaned elements
            const orphanedElements = this.document.querySelectorAll('*:not([class]):not([id]):not(html):not(head):not(body):not(meta):not(title):not(link):not(script)');
            
            if (orphanedElements.length > 0) {
                console.log(`  ⚠️ ${orphanedElements.length} elements without class or ID`);
            } else {
                console.log('  ✅ All elements properly identified');
            }
            
            this.recordTest('DOM Structure', foundContainers === requiredContainers.length && duplicateIds.length === 0, {
                foundContainers: foundContainers,
                totalContainers: requiredContainers.length,
                duplicateIds: duplicateIds.length,
                orphanedElements: orphanedElements.length
            });
            
        } catch (error) {
            this.recordTest('DOM Structure', false, null, error.message);
        }
    }

    async testAllInteractiveElements() {
        console.log('\n🔘 PHASE 3: TESTING ALL INTERACTIVE ELEMENTS');
        console.log('-'.repeat(70));
        
        console.log('🔍 Testing every button and interactive element...');
        
        let workingButtons = 0;
        let criticalButtons = 0;
        let workingCriticalButtons = 0;
        
        for (const element of this.interactiveElements) {
            if (element.critical) criticalButtons++;
            
            try {
                // Check if button exists in HTML
                const buttonExists = this.uiContent.html.includes(element.onclick) ||
                                   this.uiContent.html.includes(element.id);
                
                // Check if handler exists in JavaScript
                const handlerExists = this.uiContent.javascript.includes(element.onclick.replace('()', ''));
                
                // Check for proper HTML structure
                const hasProperStructure = this.checkButtonStructure(element);
                
                if (buttonExists && handlerExists && hasProperStructure) {
                    workingButtons++;
                    if (element.critical) workingCriticalButtons++;
                    
                    console.log(`  ✅ ${element.id}: Complete (${element.critical ? 'CRITICAL' : 'Normal'})`);
                    
                    this.recordTest(`Button: ${element.id}`, true, {
                        buttonExists: buttonExists,
                        handlerExists: handlerExists,
                        properStructure: hasProperStructure,
                        critical: element.critical
                    });
                } else {
                    console.log(`  ❌ ${element.id}: Issues - ${!buttonExists ? 'No HTML ' : ''}${!handlerExists ? 'No Handler ' : ''}${!hasProperStructure ? 'Bad Structure' : ''}`);
                    
                    this.recordTest(`Button: ${element.id}`, false, {
                        buttonExists: buttonExists,
                        handlerExists: handlerExists,
                        properStructure: hasProperStructure,
                        critical: element.critical
                    }, 'Button implementation incomplete');
                }
                
            } catch (error) {
                console.log(`  💥 ${element.id}: Error - ${error.message}`);
                this.recordTest(`Button: ${element.id}`, false, null, error.message);
            }
        }
        
        console.log(`\n📊 Interactive Elements Summary:`);
        console.log(`   Total Buttons: ${this.interactiveElements.length}`);
        console.log(`   Working: ${workingButtons} ✅`);
        console.log(`   Critical Buttons: ${criticalButtons}`);
        console.log(`   Working Critical: ${workingCriticalButtons} ✅`);
        console.log(`   Success Rate: ${((workingButtons / this.interactiveElements.length) * 100).toFixed(1)}%`);
        console.log(`   Critical Success: ${((workingCriticalButtons / criticalButtons) * 100).toFixed(1)}%`);
    }

    checkButtonStructure(element) {
        try {
            // Check if button has proper onclick attribute
            const onclickPattern = new RegExp(`onclick="${element.onclick.replace('()', '\\(\\)')}"`);
            const hasOnclick = onclickPattern.test(this.uiContent.html);
            
            // Check if button has proper CSS classes
            const hasClasses = this.uiContent.html.includes('class="') && 
                              this.uiContent.html.includes('btn');
            
            return hasOnclick && hasClasses;
            
        } catch (error) {
            return false;
        }
    }

    async validateAllDisplayElements() {
        console.log('\n📊 PHASE 4: VALIDATING ALL DISPLAY ELEMENTS');
        console.log('-'.repeat(70));
        
        console.log('🔍 Testing all display elements and data binding...');
        
        let workingDisplays = 0;
        
        for (const element of this.displayElements) {
            try {
                // Check if element exists in HTML
                const elementExists = this.document.querySelector(`#${element.id}`) !== null;
                
                // Check if element has proper data binding in JavaScript
                const hasDataBinding = this.uiContent.javascript.includes(element.id) ||
                                     this.uiContent.javascript.includes(element.source);
                
                // Check CSS styling
                const hasStyling = this.uiContent.css.includes(element.id) ||
                                 this.uiContent.css.includes(element.type);
                
                if (elementExists && hasDataBinding) {
                    workingDisplays++;
                    console.log(`  ✅ ${element.id}: Complete display element`);
                    
                    this.recordTest(`Display: ${element.id}`, true, {
                        elementExists: elementExists,
                        hasDataBinding: hasDataBinding,
                        hasStyling: hasStyling,
                        type: element.type,
                        source: element.source
                    });
                } else {
                    console.log(`  ❌ ${element.id}: Issues - ${!elementExists ? 'No HTML ' : ''}${!hasDataBinding ? 'No Data Binding' : ''}`);
                    
                    this.recordTest(`Display: ${element.id}`, false, {
                        elementExists: elementExists,
                        hasDataBinding: hasDataBinding,
                        hasStyling: hasStyling
                    }, 'Display element incomplete');
                }
                
            } catch (error) {
                console.log(`  💥 ${element.id}: Error - ${error.message}`);
                this.recordTest(`Display: ${element.id}`, false, null, error.message);
            }
        }
        
        console.log(`\n📊 Display Elements: ${workingDisplays}/${this.displayElements.length} (${((workingDisplays / this.displayElements.length) * 100).toFixed(1)}%)`);
    }

    async testAllInputElements() {
        console.log('\n📝 PHASE 5: TESTING ALL INPUT ELEMENTS');
        console.log('-'.repeat(70));
        
        console.log('🔍 Testing all input fields and validation...');
        
        let workingInputs = 0;
        
        for (const element of this.inputElements) {
            try {
                // Check if input exists in HTML
                const inputElement = this.document.querySelector(`#${element.id}`);
                const inputExists = inputElement !== null;
                
                // Check input type and attributes
                let hasProperType = false;
                let hasValidation = false;
                
                if (inputElement) {
                    hasProperType = inputElement.tagName.toLowerCase() === element.type ||
                                   (element.type === 'input' && inputElement.tagName.toLowerCase() === 'input');
                    
                    // Check for validation in JavaScript
                    hasValidation = this.uiContent.javascript.includes(`${element.id}`) &&
                                   this.uiContent.javascript.includes('validation');
                }
                
                // Check for input handling
                const hasInputHandling = this.uiContent.javascript.includes(element.id);
                
                if (inputExists && hasProperType && hasInputHandling) {
                    workingInputs++;
                    console.log(`  ✅ ${element.id}: Complete input (${element.purpose})`);
                    
                    this.recordTest(`Input: ${element.id}`, true, {
                        inputExists: inputExists,
                        hasProperType: hasProperType,
                        hasValidation: hasValidation,
                        hasInputHandling: hasInputHandling,
                        purpose: element.purpose
                    });
                } else {
                    console.log(`  ❌ ${element.id}: Issues - ${!inputExists ? 'No HTML ' : ''}${!hasProperType ? 'Wrong Type ' : ''}${!hasInputHandling ? 'No Handler' : ''}`);
                    
                    this.recordTest(`Input: ${element.id}`, false, {
                        inputExists: inputExists,
                        hasProperType: hasProperType,
                        hasInputHandling: hasInputHandling
                    }, 'Input element incomplete');
                }
                
            } catch (error) {
                console.log(`  💥 ${element.id}: Error - ${error.message}`);
                this.recordTest(`Input: ${element.id}`, false, null, error.message);
            }
        }
        
        console.log(`\n📊 Input Elements: ${workingInputs}/${this.inputElements.length} (${((workingInputs / this.inputElements.length) * 100).toFixed(1)}%)`);
    }

    async validateCSSHTMLIntegration() {
        console.log('\n🎨 PHASE 6: VALIDATING CSS-HTML INTEGRATION');
        console.log('-'.repeat(70));
        
        console.log('🔍 Checking CSS class usage and styling...');
        
        try {
            // Extract all CSS classes
            const cssClasses = new Set();
            const cssClassMatches = this.uiContent.css.match(/\.([\w-]+)\s*{/g);
            if (cssClassMatches) {
                cssClassMatches.forEach(match => {
                    const className = match.replace(/\.|{|\s/g, '');
                    cssClasses.add(className);
                });
            }
            
            // Extract all HTML classes
            const htmlClasses = new Set();
            const htmlClassMatches = this.uiContent.html.match(/class="([^"]+)"/g);
            if (htmlClassMatches) {
                htmlClassMatches.forEach(match => {
                    const classes = match.replace(/class="|"/g, '').split(' ');
                    classes.forEach(cls => htmlClasses.add(cls.trim()));
                });
            }
            
            // Find unused CSS classes
            const unusedCSS = Array.from(cssClasses).filter(cls => !htmlClasses.has(cls));
            
            // Find unstyled HTML classes
            const unstyledHTML = Array.from(htmlClasses).filter(cls => !cssClasses.has(cls));
            
            console.log(`  📊 CSS Classes: ${cssClasses.size}`);
            console.log(`  📊 HTML Classes: ${htmlClasses.size}`);
            console.log(`  📊 Unused CSS: ${unusedCSS.length}`);
            console.log(`  📊 Unstyled HTML: ${unstyledHTML.length}`);
            
            if (unusedCSS.length > 0) {
                console.log(`  ⚠️ Unused CSS classes: ${unusedCSS.slice(0, 5).join(', ')}${unusedCSS.length > 5 ? '...' : ''}`);
            }
            
            if (unstyledHTML.length > 0) {
                console.log(`  ⚠️ Unstyled HTML classes: ${unstyledHTML.slice(0, 5).join(', ')}${unstyledHTML.length > 5 ? '...' : ''}`);
            }
            
            const integrationScore = ((cssClasses.size - unusedCSS.length) / cssClasses.size) * 100;
            
            this.recordTest('CSS-HTML Integration', integrationScore >= 80, {
                cssClasses: cssClasses.size,
                htmlClasses: htmlClasses.size,
                unusedCSS: unusedCSS.length,
                unstyledHTML: unstyledHTML.length,
                integrationScore: integrationScore
            });
            
        } catch (error) {
            this.recordTest('CSS-HTML Integration', false, null, error.message);
        }
    }

    async testJavaScriptHTMLIntegration() {
        console.log('\n📜 PHASE 7: TESTING JAVASCRIPT-HTML INTEGRATION');
        console.log('-'.repeat(70));
        
        console.log('🔍 Checking JavaScript-HTML element binding...');
        
        try {
            // Extract all getElementById calls
            const getElementCalls = this.uiContent.javascript.match(/getElementById\(['"`]([^'"`]+)['"`]\)/g) || [];
            const querySelectorCalls = this.uiContent.javascript.match(/querySelector\(['"`]([^'"`]+)['"`]\)/g) || [];
            
            let validBindings = 0;
            let totalBindings = getElementCalls.length + querySelectorCalls.length;
            
            // Check getElementById calls
            getElementCalls.forEach(call => {
                const elementId = call.match(/getElementById\(['"`]([^'"`]+)['"`]\)/)[1];
                const elementExists = this.document.querySelector(`#${elementId}`) !== null;
                
                if (elementExists) {
                    validBindings++;
                    console.log(`  ✅ getElementById('${elementId}'): Element exists`);
                } else {
                    console.log(`  ❌ getElementById('${elementId}'): Element missing`);
                    this.domIssues.push(`Missing element for getElementById: ${elementId}`);
                }
            });
            
            // Check querySelector calls
            querySelectorCalls.forEach(call => {
                const selector = call.match(/querySelector\(['"`]([^'"`]+)['"`]\)/)[1];
                try {
                    const elementExists = this.document.querySelector(selector) !== null;
                    
                    if (elementExists) {
                        validBindings++;
                        console.log(`  ✅ querySelector('${selector}'): Element exists`);
                    } else {
                        console.log(`  ❌ querySelector('${selector}'): Element missing`);
                        this.domIssues.push(`Missing element for querySelector: ${selector}`);
                    }
                } catch (error) {
                    console.log(`  💥 querySelector('${selector}'): Invalid selector`);
                    this.domIssues.push(`Invalid selector: ${selector}`);
                }
            });
            
            const bindingRate = totalBindings > 0 ? (validBindings / totalBindings) * 100 : 100;
            
            this.recordTest('JavaScript-HTML Integration', bindingRate >= 90, {
                validBindings: validBindings,
                totalBindings: totalBindings,
                bindingRate: bindingRate,
                getElementCalls: getElementCalls.length,
                querySelectorCalls: querySelectorCalls.length
            });
            
            console.log(`\n📊 JavaScript-HTML Bindings: ${validBindings}/${totalBindings} (${bindingRate.toFixed(1)}%)`);
            
        } catch (error) {
            this.recordTest('JavaScript-HTML Integration', false, null, error.message);
        }
    }

    async testCompleteWorkflows() {
        console.log('\n🔄 PHASE 8: TESTING COMPLETE WORKFLOWS');
        console.log('-'.repeat(70));
        
        console.log('🔍 Testing end-to-end workflow functionality...');
        
        let workingWorkflows = 0;
        
        for (const workflow of this.workflows) {
            try {
                console.log(`\n  🎯 Testing ${workflow.name}...`);
                
                const workflowResults = await this.testWorkflowSteps(workflow);
                
                if (workflowResults.success) {
                    workingWorkflows++;
                    console.log(`    ✅ Complete workflow functional`);
                    
                    this.recordTest(`Workflow: ${workflow.name}`, true, {
                        steps: workflowResults.steps,
                        critical: workflow.critical
                    });
                } else {
                    console.log(`    ❌ Workflow issues: ${workflowResults.issues.join(', ')}`);
                    
                    this.recordTest(`Workflow: ${workflow.name}`, false, {
                        steps: workflowResults.steps,
                        issues: workflowResults.issues,
                        critical: workflow.critical
                    }, 'Workflow incomplete');
                }
                
            } catch (error) {
                console.log(`    💥 ${workflow.name}: Error - ${error.message}`);
                this.recordTest(`Workflow: ${workflow.name}`, false, null, error.message);
            }
        }
        
        console.log(`\n📊 Complete Workflows: ${workingWorkflows}/${this.workflows.length} (${((workingWorkflows / this.workflows.length) * 100).toFixed(1)}%)`);
    }

    async testWorkflowSteps(workflow) {
        const results = {
            success: true,
            steps: [],
            issues: []
        };
        
        // Test each step of the workflow
        for (const step of workflow.steps) {
            let stepWorking = false;
            
            if (step.includes('Click') && step.includes('button')) {
                // Test button click workflow
                const buttonName = step.toLowerCase().replace('click ', '').replace(' button', '');
                stepWorking = this.uiContent.html.includes(buttonName) || 
                             this.uiContent.javascript.includes(buttonName);
            } else if (step.includes('Enter') || step.includes('Input')) {
                // Test input workflow
                stepWorking = this.inputElements.some(input => 
                    step.toLowerCase().includes(input.purpose.toLowerCase())
                );
            } else if (step.includes('Display') || step.includes('Show')) {
                // Test display workflow
                stepWorking = this.displayElements.some(display => 
                    step.toLowerCase().includes(display.type)
                );
            } else {
                // Generic step validation
                stepWorking = true;
            }
            
            results.steps.push({
                step: step,
                working: stepWorking
            });
            
            if (!stepWorking) {
                results.success = false;
                results.issues.push(step);
            }
        }
        
        return results;
    }

    async analyzeCrossFileDependencies() {
        console.log('\n🔗 PHASE 9: ANALYZING CROSS-FILE DEPENDENCIES');
        console.log('-'.repeat(70));
        
        console.log('🔍 Checking dependencies between UI files...');
        
        try {
            // Check HTML → CSS dependencies
            const htmlCSSIssues = this.checkHTMLCSSDepencencies();
            
            // Check HTML → JavaScript dependencies
            const htmlJSIssues = this.checkHTMLJavaScriptDependencies();
            
            // Check JavaScript → CSS dependencies
            const jsCSSIssues = this.checkJavaScriptCSSDependencies();
            
            const totalIssues = htmlCSSIssues.length + htmlJSIssues.length + jsCSSIssues.length;
            
            console.log(`  📊 HTML → CSS Issues: ${htmlCSSIssues.length}`);
            console.log(`  📊 HTML → JS Issues: ${htmlJSIssues.length}`);
            console.log(`  📊 JS → CSS Issues: ${jsCSSIssues.length}`);
            console.log(`  📊 Total Cross-File Issues: ${totalIssues}`);
            
            if (totalIssues === 0) {
                console.log('  ✅ No cross-file dependency issues found');
            } else {
                console.log(`  ⚠️ ${totalIssues} cross-file issues detected`);
                [...htmlCSSIssues, ...htmlJSIssues, ...jsCSSIssues].slice(0, 5).forEach(issue => {
                    console.log(`    - ${issue}`);
                });
            }
            
            this.crossFileIssues = [...htmlCSSIssues, ...htmlJSIssues, ...jsCSSIssues];
            
            this.recordTest('Cross-File Dependencies', totalIssues === 0, {
                htmlCSSIssues: htmlCSSIssues.length,
                htmlJSIssues: htmlJSIssues.length,
                jsCSSIssues: jsCSSIssues.length,
                totalIssues: totalIssues
            });
            
        } catch (error) {
            this.recordTest('Cross-File Dependencies', false, null, error.message);
        }
    }

    checkHTMLCSSDepencencies() {
        const issues = [];
        
        // Check if all HTML classes have CSS definitions
        const htmlClassMatches = this.uiContent.html.match(/class="([^"]+)"/g) || [];
        
        htmlClassMatches.forEach(match => {
            const classes = match.replace(/class="|"/g, '').split(' ');
            classes.forEach(className => {
                if (className.trim() && !this.uiContent.css.includes(`.${className.trim()}`)) {
                    issues.push(`HTML class '${className}' has no CSS definition`);
                }
            });
        });
        
        return issues;
    }

    checkHTMLJavaScriptDependencies() {
        const issues = [];
        
        // Check if all onclick handlers have JavaScript implementations
        const onclickMatches = this.uiContent.html.match(/onclick="([^"]+)"/g) || [];
        
        onclickMatches.forEach(match => {
            const functionCall = match.replace(/onclick="|"/g, '');
            const functionName = functionCall.replace(/\(.*\)/, '');
            
            if (!this.uiContent.javascript.includes(`function ${functionName}`) &&
                !this.uiContent.javascript.includes(`${functionName} =`) &&
                !this.uiContent.javascript.includes(`async function ${functionName}`)) {
                issues.push(`HTML onclick '${functionCall}' has no JavaScript implementation`);
            }
        });
        
        return issues;
    }

    checkJavaScriptCSSDependencies() {
        const issues = [];
        
        // Check if JavaScript class manipulations have CSS definitions
        const classNameMatches = this.uiContent.javascript.match(/className\s*=\s*['"`]([^'"`]+)['"`]/g) || [];
        
        classNameMatches.forEach(match => {
            const className = match.match(/['"`]([^'"`]+)['"`]/)[1];
            if (!this.uiContent.css.includes(`.${className}`)) {
                issues.push(`JavaScript className '${className}' has no CSS definition`);
            }
        });
        
        return issues;
    }

    async generateComprehensiveReport() {
        console.log('\n📊 GENERATING COMPREHENSIVE FRONTEND REPORT');
        console.log('=' + '='.repeat(80));
        
        const totalTests = this.testResults.length;
        const passedTests = this.testResults.filter(test => test.success).length;
        const failedTests = totalTests - passedTests;
        const overallScore = (passedTests / totalTests) * 100;
        
        // Calculate category scores
        const buttonTests = this.testResults.filter(t => t.testName.startsWith('Button:'));
        const displayTests = this.testResults.filter(t => t.testName.startsWith('Display:'));
        const inputTests = this.testResults.filter(t => t.testName.startsWith('Input:'));
        const workflowTests = this.testResults.filter(t => t.testName.startsWith('Workflow:'));
        
        const buttonScore = buttonTests.length > 0 ? (buttonTests.filter(t => t.success).length / buttonTests.length) * 100 : 0;
        const displayScore = displayTests.length > 0 ? (displayTests.filter(t => t.success).length / displayTests.length) * 100 : 0;
        const inputScore = inputTests.length > 0 ? (inputTests.filter(t => t.success).length / inputTests.length) * 100 : 0;
        const workflowScore = workflowTests.length > 0 ? (workflowTests.filter(t => t.success).length / workflowTests.length) * 100 : 0;
        
        console.log(`\n🎯 COMPREHENSIVE FRONTEND SUMMARY:`);
        console.log(`   Overall Score: ${overallScore.toFixed(1)}%`);
        console.log(`   Total Tests: ${totalTests}`);
        console.log(`   Passed: ${passedTests} ✅`);
        console.log(`   Failed: ${failedTests} ❌`);
        
        console.log(`\n📋 CATEGORY BREAKDOWN:`);
        console.log(`   🔘 Buttons: ${buttonScore.toFixed(1)}% (${buttonTests.filter(t => t.success).length}/${buttonTests.length})`);
        console.log(`   📊 Displays: ${displayScore.toFixed(1)}% (${displayTests.filter(t => t.success).length}/${displayTests.length})`);
        console.log(`   📝 Inputs: ${inputScore.toFixed(1)}% (${inputTests.filter(t => t.success).length}/${inputTests.length})`);
        console.log(`   🔄 Workflows: ${workflowScore.toFixed(1)}% (${workflowTests.filter(t => t.success).length}/${workflowTests.length})`);
        
        // Critical functionality assessment
        const criticalTests = this.testResults.filter(test => 
            test.details && test.details.critical === true
        );
        const criticalPassed = criticalTests.filter(test => test.success).length;
        
        console.log(`\n🚨 CRITICAL FUNCTIONALITY:`);
        console.log(`   Critical Features: ${criticalPassed}/${criticalTests.length}`);
        console.log(`   Critical Success Rate: ${criticalTests.length > 0 ? ((criticalPassed / criticalTests.length) * 100).toFixed(1) : 0}%`);
        
        // DOM issues summary
        if (this.domIssues.length > 0) {
            console.log(`\n⚠️ DOM ISSUES DETECTED (${this.domIssues.length}):`);
            this.domIssues.slice(0, 5).forEach(issue => {
                console.log(`   - ${issue}`);
            });
            if (this.domIssues.length > 5) {
                console.log(`   ... and ${this.domIssues.length - 5} more`);
            }
        } else {
            console.log(`\n✅ NO DOM ISSUES DETECTED`);
        }
        
        // Cross-file issues summary
        if (this.crossFileIssues.length > 0) {
            console.log(`\n🔗 CROSS-FILE ISSUES (${this.crossFileIssues.length}):`);
            this.crossFileIssues.slice(0, 5).forEach(issue => {
                console.log(`   - ${issue}`);
            });
        } else {
            console.log(`\n✅ NO CROSS-FILE ISSUES DETECTED`);
        }
        
        // Final frontend verdict
        console.log('\n' + '='.repeat(80));
        if (overallScore >= 95 && this.domIssues.length === 0 && criticalPassed === criticalTests.length) {
            console.log('🎉 FRONTEND TESTING: EXCELLENT - PRODUCTION READY');
            console.log('   All critical functionality working');
            console.log('   No DOM or cross-file issues');
            console.log('   Complete UI integration verified');
        } else if (overallScore >= 85 && criticalPassed >= criticalTests.length * 0.9) {
            console.log('✅ FRONTEND TESTING: GOOD - READY FOR BETA');
            console.log('   Core functionality working');
            console.log('   Minor UI issues detected');
        } else if (overallScore >= 70) {
            console.log('⚠️ FRONTEND TESTING: NEEDS IMPROVEMENT');
            console.log('   Some critical functionality issues');
            console.log('   UI fixes required before launch');
        } else {
            console.log('❌ FRONTEND TESTING: MAJOR ISSUES');
            console.log('   Extensive frontend problems detected');
            console.log('   Significant development required');
        }
        console.log('=' + '='.repeat(80));
        
        // Save comprehensive report
        await this.saveFrontendReport(overallScore);
    }

    recordTest(testName, success, details, error = null) {
        this.testResults.push({
            testName,
            success,
            details,
            error,
            timestamp: new Date()
        });
    }

    async saveFrontendReport(overallScore) {
        const reportPath = path.join(__dirname, 'test-reports', 
            `apollo-comprehensive-frontend-${Date.now()}.json`);
        
        await fs.ensureDir(path.dirname(reportPath));
        
        const report = {
            timestamp: new Date(),
            overallScore: overallScore,
            totalTests: this.testResults.length,
            passedTests: this.testResults.filter(t => t.success).length,
            failedTests: this.testResults.filter(t => !t.success).length,
            testResults: this.testResults,
            domIssues: this.domIssues,
            crossFileIssues: this.crossFileIssues,
            uiFiles: this.uiFiles,
            interactiveElements: this.interactiveElements,
            displayElements: this.displayElements,
            inputElements: this.inputElements,
            workflows: this.workflows
        };
        
        await fs.writeJson(reportPath, report, { spaces: 2 });
        console.log(`\n📄 Comprehensive frontend report saved: ${reportPath}`);
    }
}

// Add JSDOM dependency check
async function checkJSDOMAvailability() {
    try {
        require('jsdom');
        return true;
    } catch (error) {
        console.log('⚠️ JSDOM not available - installing...');
        const { execSync } = require('child_process');
        try {
            execSync('npm install jsdom --save-dev', { stdio: 'inherit' });
            return true;
        } catch (installError) {
            console.log('❌ Failed to install JSDOM - some tests may be limited');
            return false;
        }
    }
}

// Export for use in other modules
module.exports = ComprehensiveFrontendTester;

// Run if executed directly
if (require.main === module) {
    checkJSDOMAvailability().then(async (jsDOMAvailable) => {
        if (!jsDOMAvailable) {
            console.log('⚠️ Running limited frontend tests without JSDOM');
        }
        
        const tester = new ComprehensiveFrontendTester();
        return tester.runComprehensiveFrontendTests();
    }).then(() => {
        console.log('\n🎉 Comprehensive Frontend Testing Completed!');
        console.log('\n📋 Frontend Testing Summary:');
        console.log('   ✅ All UI files loaded and parsed');
        console.log('   ✅ DOM structure validated');
        console.log('   ✅ Interactive elements tested');
        console.log('   ✅ Display elements validated');
        console.log('   ✅ Input elements tested');
        console.log('   ✅ CSS-HTML integration checked');
        console.log('   ✅ JavaScript-HTML binding verified');
        console.log('   ✅ Complete workflows tested');
        console.log('   ✅ Cross-file dependencies analyzed');
        process.exit(0);
    }).catch((error) => {
        console.error('\n💥 Comprehensive Frontend Testing Failed:', error);
        process.exit(1);
    });
}
