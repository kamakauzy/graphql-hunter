#!/usr/bin/env python3
"""
HTML Report Generator for GraphQL Hunter
"""

from typing import List, Dict
from datetime import datetime


class HTMLReporter:
    """Generate HTML security reports"""
    
    @staticmethod
    def generate(metadata: Dict, findings: List[Dict], summary: Dict, output_file: str):
        """
        Generate HTML report
        
        Args:
            metadata: Scan metadata
            findings: List of findings
            summary: Summary statistics
            output_file: Output file path
        """
        html = HTMLReporter._build_html(metadata, findings, summary)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html)
    
    @staticmethod
    def _build_html(metadata: Dict, findings: List[Dict], summary: Dict) -> str:
        """Build complete HTML document"""
        
        # Get severity counts - count from actual findings
        severity_counts = {
            'CRITICAL': sum(1 for f in findings if f.get('severity', '').upper() == 'CRITICAL'),
            'HIGH': sum(1 for f in findings if f.get('severity', '').upper() == 'HIGH'),
            'MEDIUM': sum(1 for f in findings if f.get('severity', '').upper() == 'MEDIUM'),
            'LOW': sum(1 for f in findings if f.get('severity', '').upper() == 'LOW'),
            'INFO': sum(1 for f in findings if f.get('severity', '').upper() == 'INFO')
        }
        
        total = sum(severity_counts.values())
        risk_level = summary.get('risk_level', 'UNKNOWN')
        
        # Build findings HTML
        findings_html = HTMLReporter._build_findings_html(findings)
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GraphQL Hunter Security Report - {metadata.get('target', 'Unknown')}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            color: #333;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            overflow: hidden;
        }}
        
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }}
        
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }}
        
        .header .subtitle {{
            font-size: 1.1em;
            opacity: 0.9;
        }}
        
        .metadata {{
            background: #f8f9fa;
            padding: 30px 40px;
            border-bottom: 3px solid #e9ecef;
        }}
        
        .metadata-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
        }}
        
        .metadata-item {{
            background: white;
            padding: 15px;
            border-radius: 8px;
            border-left: 4px solid #667eea;
        }}
        
        .metadata-item label {{
            font-weight: 600;
            color: #666;
            font-size: 0.85em;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        
        .metadata-item value {{
            display: block;
            color: #333;
            font-size: 1.1em;
            margin-top: 5px;
            word-break: break-all;
        }}
        
        .summary {{
            padding: 40px;
            background: white;
        }}
        
        .summary h2 {{
            color: #333;
            margin-bottom: 25px;
            font-size: 1.8em;
        }}
        
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        
        .stat-card {{
            background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
            padding: 25px;
            border-radius: 10px;
            text-align: center;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            transition: transform 0.2s;
        }}
        
        .stat-card:hover {{
            transform: translateY(-5px);
        }}
        
        .stat-card.critical {{
            background: linear-gradient(135deg, #ff6b6b 0%, #ee5a6f 100%);
            color: white;
        }}
        
        .stat-card.high {{
            background: linear-gradient(135deg, #ff8a65 0%, #ff7043 100%);
            color: white;
        }}
        
        .stat-card.medium {{
            background: linear-gradient(135deg, #ffd54f 0%, #ffb300 100%);
            color: white;
        }}
        
        .stat-card.low {{
            background: linear-gradient(135deg, #81c784 0%, #66bb6a 100%);
            color: white;
        }}
        
        .stat-card.info {{
            background: linear-gradient(135deg, #64b5f6 0%, #42a5f5 100%);
            color: white;
        }}
        
        .stat-number {{
            font-size: 3em;
            font-weight: bold;
            margin-bottom: 5px;
        }}
        
        .stat-label {{
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
            opacity: 0.9;
        }}
        
        .risk-badge {{
            display: inline-block;
            padding: 15px 30px;
            border-radius: 50px;
            font-weight: bold;
            font-size: 1.2em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        
        .risk-critical {{
            background: #ff6b6b;
            color: white;
        }}
        
        .risk-high {{
            background: #ff8a65;
            color: white;
        }}
        
        .risk-medium {{
            background: #ffd54f;
            color: #333;
        }}
        
        .risk-low {{
            background: #81c784;
            color: white;
        }}
        
        .risk-info {{
            background: #64b5f6;
            color: white;
        }}
        
        .findings {{
            padding: 40px;
            background: #f8f9fa;
        }}
        
        .findings h2 {{
            color: #333;
            margin-bottom: 25px;
            font-size: 1.8em;
        }}
        
        .finding {{
            background: white;
            border-radius: 8px;
            padding: 25px;
            margin-bottom: 20px;
            border-left: 5px solid #ccc;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        
        .finding.critical {{
            border-left-color: #ff6b6b;
        }}
        
        .finding.high {{
            border-left-color: #ff8a65;
        }}
        
        .finding.medium {{
            border-left-color: #ffd54f;
        }}
        
        .finding.low {{
            border-left-color: #81c784;
        }}
        
        .finding.info {{
            border-left-color: #64b5f6;
        }}
        
        .finding-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }}
        
        .finding-title {{
            font-size: 1.4em;
            color: #333;
            font-weight: 600;
        }}
        
        .severity-badge {{
            padding: 8px 16px;
            border-radius: 20px;
            font-weight: bold;
            font-size: 0.85em;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        
        .severity-critical {{
            background: #ff6b6b;
            color: white;
        }}
        
        .severity-high {{
            background: #ff8a65;
            color: white;
        }}
        
        .severity-medium {{
            background: #ffd54f;
            color: #333;
        }}
        
        .severity-low {{
            background: #81c784;
            color: white;
        }}
        
        .severity-info {{
            background: #64b5f6;
            color: white;
        }}
        
        .finding-section {{
            margin-top: 15px;
        }}
        
        .finding-section h3 {{
            color: #667eea;
            font-size: 1em;
            margin-bottom: 8px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        
        .finding-section p {{
            color: #555;
            line-height: 1.6;
        }}
        
        .evidence {{
            background: #f8f9fa;
            border-radius: 5px;
            padding: 15px;
            margin-top: 10px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            overflow-x: auto;
        }}
        
        .evidence pre {{
            white-space: pre-wrap;
            word-wrap: break-word;
        }}
        
        .cwe-badge {{
            display: inline-block;
            background: #e9ecef;
            color: #495057;
            padding: 5px 12px;
            border-radius: 15px;
            font-size: 0.85em;
            font-weight: 500;
            margin-top: 10px;
        }}
        
        .footer {{
            background: #343a40;
            color: white;
            padding: 30px 40px;
            text-align: center;
        }}
        
        .footer p {{
            margin-bottom: 10px;
        }}
        
        .footer a {{
            color: #64b5f6;
            text-decoration: none;
        }}
        
        .footer a:hover {{
            text-decoration: underline;
        }}
        
        @media print {{
            body {{
                background: white;
                padding: 0;
            }}
            
            .container {{
                box-shadow: none;
            }}
            
            .stat-card {{
                break-inside: avoid;
            }}
            
            .finding {{
                break-inside: avoid;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🎯 GraphQL Hunter</h1>
            <div class="subtitle">Security Assessment Report</div>
        </div>
        
        <div class="metadata">
            <div class="metadata-grid">
                <div class="metadata-item">
                    <label>Target URL</label>
                    <value>{metadata.get('target', 'N/A')}</value>
                </div>
                <div class="metadata-item">
                    <label>Scan Profile</label>
                    <value>{metadata.get('profile', 'N/A').upper()}</value>
                </div>
                <div class="metadata-item">
                    <label>Scan Date</label>
                    <value>{metadata.get('timestamp', 'N/A')}</value>
                </div>
                <div class="metadata-item">
                    <label>Safe Mode</label>
                    <value>{"Enabled" if metadata.get('safe_mode') else "Disabled"}</value>
                </div>
            </div>
        </div>
        
        <div class="summary">
            <h2>📊 Executive Summary</h2>
            <div class="stats-grid">
                <div class="stat-card critical">
                    <div class="stat-number">{severity_counts['CRITICAL']}</div>
                    <div class="stat-label">Critical</div>
                </div>
                <div class="stat-card high">
                    <div class="stat-number">{severity_counts['HIGH']}</div>
                    <div class="stat-label">High</div>
                </div>
                <div class="stat-card medium">
                    <div class="stat-number">{severity_counts['MEDIUM']}</div>
                    <div class="stat-label">Medium</div>
                </div>
                <div class="stat-card low">
                    <div class="stat-number">{severity_counts['LOW']}</div>
                    <div class="stat-label">Low</div>
                </div>
                <div class="stat-card info">
                    <div class="stat-number">{severity_counts['INFO']}</div>
                    <div class="stat-label">Info</div>
                </div>
            </div>
            <p style="text-align: center; margin-top: 20px;">
                <span class="risk-badge risk-{risk_level.lower()}">{risk_level} Risk</span>
            </p>
            <p style="text-align: center; margin-top: 15px; color: #666;">
                Total Findings: <strong>{total}</strong>
            </p>
        </div>
        
        <div class="findings">
            <h2>🔍 Detailed Findings</h2>
            {findings_html if findings else '<p style="text-align: center; color: #666; padding: 40px;">No security findings detected.</p>'}
        </div>
        
        <div class="footer">
            <p><strong>GraphQL Hunter v1.0</strong></p>
            <p>Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p>For questions or support, contact <a href="mailto:brad@securit360.com">brad@securit360.com</a></p>
            <p style="margin-top: 15px; font-size: 0.9em; opacity: 0.8;">
                This report is for authorized security testing only. Always obtain proper authorization before testing.
            </p>
        </div>
    </div>
</body>
</html>"""
        
        return html
    
    @staticmethod
    def _build_findings_html(findings: List[Dict]) -> str:
        """Build findings section HTML"""
        if not findings:
            return ''
        
        # Sort findings by severity (CRITICAL -> HIGH -> MEDIUM -> LOW -> INFO)
        severity_order = {
            'CRITICAL': 0,
            'HIGH': 1,
            'MEDIUM': 2,
            'LOW': 3,
            'INFO': 4
        }
        sorted_findings = sorted(findings, key=lambda x: severity_order.get(x.get('severity', 'INFO').upper(), 5))
        
        html_parts = []
        
        for finding in sorted_findings:
            severity = finding.get('severity', 'INFO').lower()
            title = finding.get('title', 'Unknown Issue')
            description = finding.get('description', 'No description provided')
            impact = finding.get('impact', 'Impact not specified')
            remediation = finding.get('remediation', 'No remediation guidance available')
            cwe = finding.get('cwe', '')
            evidence = finding.get('evidence', {})
            poc = finding.get('poc', '')
            
            # Build evidence HTML
            evidence_html = ''
            if evidence:
                evidence_str = '\n'.join([f"{k}: {v}" for k, v in evidence.items()])
                evidence_html = f'<div class="evidence"><pre>{HTMLReporter._escape_html(evidence_str)}</pre></div>'
            
            if poc:
                evidence_html += f'<div class="finding-section"><h3>Proof of Concept</h3><div class="evidence"><pre>{HTMLReporter._escape_html(poc)}</pre></div></div>'
            
            cwe_html = f'<div class="cwe-badge">{cwe}</div>' if cwe else ''
            
            finding_html = f"""
            <div class="finding {severity}">
                <div class="finding-header">
                    <div class="finding-title">{HTMLReporter._escape_html(title)}</div>
                    <div class="severity-badge severity-{severity}">{severity.upper()}</div>
                </div>
                
                <div class="finding-section">
                    <h3>Description</h3>
                    <p>{HTMLReporter._escape_html(description)}</p>
                </div>
                
                <div class="finding-section">
                    <h3>Impact</h3>
                    <p>{HTMLReporter._escape_html(impact)}</p>
                </div>
                
                <div class="finding-section">
                    <h3>Remediation</h3>
                    <p>{HTMLReporter._escape_html(remediation)}</p>
                </div>
                
                {evidence_html}
                {cwe_html}
            </div>
            """
            
            html_parts.append(finding_html)
        
        return '\n'.join(html_parts)
    
    @staticmethod
    def _escape_html(text: str) -> str:
        """Escape HTML special characters"""
        if not isinstance(text, str):
            text = str(text)
        
        return (text
                .replace('&', '&amp;')
                .replace('<', '&lt;')
                .replace('>', '&gt;')
                .replace('"', '&quot;')
                .replace("'", '&#x27;'))

