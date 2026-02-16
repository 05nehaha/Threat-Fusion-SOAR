import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages
import os

def generate_visual_report(scan_id, nmap_data, detected_vulns, final_cve_list, output_path):
    """
    Professional Dashboard: Fixed overlapping labels and improved spacing.
    """
    # 1. PREPARE DATA
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for item in final_cve_list:
        for cve_entry in item.get('cve', []):
            if "[CRITICAL" in cve_entry: severity_counts["CRITICAL"] += 1
            elif "[HIGH" in cve_entry: severity_counts["HIGH"] += 1
            elif "[MEDIUM" in cve_entry: severity_counts["MEDIUM"] += 1
            elif "[LOW" in cve_entry: severity_counts["LOW"] += 1

    severity_data = {k: v for k, v in severity_counts.items() if v > 0}
    
    # Clean up port labels to prevent overlapping
    open_ports = []
    for s in nmap_data:
        if s.get('state') == 'open':
            name = s.get('name', 'unknown')
            # Shorten very long admin-panel strings for the chart
            if "POTENTIAL-ADMIN-PANEL" in name:
                name = "ADMIN-PANEL"
            open_ports.append(f"{s.get('port')}\n{name}")

    attack_counts = {vuln: 1 for vuln in detected_vulns} 

    # 2. CREATE PDF
    with PdfPages(output_path) as pdf:
        # Taller figure to give breathing room
        fig = plt.figure(figsize=(10, 14)) 
        fig.suptitle(f"SECURITY POSTURE DASHBOARD - SCAN #{scan_id}", fontsize=18, fontweight='bold', y=0.96)
        
        # --- CHART 1: SEVERITY (Pie) ---
        ax1 = plt.subplot(3, 1, 1)
        if severity_data:
            colors_map = {'CRITICAL': '#d32f2f', 'HIGH': '#f57c00', 'MEDIUM': '#fbc02d', 'LOW': '#388e3c'}
            chart_colors = [colors_map.get(k, 'gray') for k in severity_data.keys()]
            # Added shadows and startangle for a modern look
            ax1.pie(severity_data.values(), labels=severity_data.keys(), autopct='%1.1f%%', 
                    colors=chart_colors, startangle=140, pctdistance=0.85, explode=[0.05]*len(severity_data))
            ax1.set_title("Vulnerability Severity Distribution", fontsize=14, fontweight='bold', pad=15)
        else:
            ax1.text(0.5, 0.5, "No Severity Data Available", ha='center', fontsize=12, color='gray')
            ax1.axis('off')

        # --- CHART 2: PORTS (Vertical Bar) ---
        ax2 = plt.subplot(3, 1, 2)
        if open_ports:
            # Use a slightly thinner bar and vertical labels
            bars = ax2.bar(open_ports, [1]*len(open_ports), color='#0288d1', edgecolor='black', alpha=0.7)
            ax2.set_title("Open Ports & Services", fontsize=14, fontweight='bold', pad=15)
            ax2.set_yticks([]) 
            # Rotate labels to prevent collision seen in your image
            plt.xticks(fontsize=9, fontweight='medium') 
        else:
            ax2.text(0.5, 0.5, "No Open Ports Detected", ha='center', fontsize=12, color='gray')
            ax2.axis('off')

        # --- CHART 3: THREAT VECTORS (Horizontal Bar) ---
        ax3 = plt.subplot(3, 1, 3)
        if attack_counts:
            sorted_attacks = sorted(attack_counts.keys())
            y_pos = range(len(sorted_attacks))
            ax3.barh(y_pos, [1]*len(sorted_attacks), color='#ef6c00', edgecolor='black', height=0.6)
            ax3.set_yticks(y_pos)
            ax3.set_yticklabels(sorted_attacks, fontsize=10)
            ax3.set_title("Threat Vectors Identified", fontsize=14, fontweight='bold', pad=15)
            ax3.set_xticks([])
            ax3.invert_yaxis() # Highest priority at the top
        else:
            ax3.text(0.5, 0.5, "No Active Threats Detected", ha='center', fontsize=12, color='gray')
            ax3.axis('off')

        # Final layout adjustments to prevent the "disaster" overlap
        plt.subplots_adjust(hspace=0.4, top=0.9) 
        plt.tight_layout(rect=[0.05, 0.05, 0.95, 0.92]) 
        
        pdf.savefig(fig)
        plt.close()

    print(f"[*] Visual Report Optimized: {output_path}")