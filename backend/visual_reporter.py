import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages
import os

def generate_visual_report(scan_id, nmap_data, detected_vulns, final_cve_list, output_path):
    """
    Generates a PDF Dashboard containing 3 charts on a SINGLE page.
    """
    
    # --- 1. PREPARE DATA ---
    
    # A. Severity Counts
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for item in final_cve_list:
        for cve_entry in item.get('cve', []):
            if "[CRITICAL" in cve_entry: severity_counts["CRITICAL"] += 1
            elif "[HIGH" in cve_entry: severity_counts["HIGH"] += 1
            elif "[MEDIUM" in cve_entry: severity_counts["MEDIUM"] += 1
            elif "[LOW" in cve_entry: severity_counts["LOW"] += 1

    # Filter out zero values
    severity_data = {k: v for k, v in severity_counts.items() if v > 0}

    # B. Open Ports
    open_ports = []
    for service in nmap_data:
        if service.get('state') == 'open':
            port_label = f"{service.get('port')}/{service.get('name')}"
            open_ports.append(port_label)
    
    # C. Attack Types (Fixing the cut-off text issue)
    attack_counts = {vuln: 1 for vuln in detected_vulns} 

    # --- 2. DRAW DASHBOARD (All on 1 Page) ---
    
    with PdfPages(output_path) as pdf:
        # Create a single page with 3 rows
        fig = plt.figure(figsize=(8.5, 11)) # Standard Letter paper size
        fig.suptitle(f"Visual Security Summary - Scan #{scan_id}", fontsize=16, fontweight='bold')
        
        # --- CHART 1: SEVERITY (Top) ---
        ax1 = plt.subplot(3, 1, 1) # 3 rows, 1 col, pos 1
        if severity_data:
            colors = {'CRITICAL': '#ff4d4d', 'HIGH': '#ff944d', 'MEDIUM': '#ffda4d', 'LOW': '#a3ff4d'}
            chart_colors = [colors.get(k, 'gray') for k in severity_data.keys()]
            ax1.pie(severity_data.values(), labels=severity_data.keys(), autopct='%1.1f%%', colors=chart_colors)
            ax1.set_title("Vulnerability Severity Distribution")
        else:
            ax1.text(0.5, 0.5, "No Vulnerabilities Found", ha='center', va='center')
            ax1.axis('off')

        # --- CHART 2: OPEN PORTS (Middle) ---
        ax2 = plt.subplot(3, 1, 2) # Pos 2
        if open_ports:
            ax2.bar(open_ports, [1]*len(open_ports), color='skyblue', width=0.4)
            ax2.set_yticks([]) # Hide y-axis
            ax2.set_title("Open Ports Detected")
        else:
            ax2.text(0.5, 0.5, "No Open Ports Found", ha='center', va='center')
            ax2.axis('off')

        # --- CHART 3: ATTACK CATEGORIES (Bottom) ---
        ax3 = plt.subplot(3, 1, 3) # Pos 3
        if attack_counts:
            # Sort for better visuals
            sorted_attacks = sorted(attack_counts.keys())
            y_pos = range(len(sorted_attacks))
            
            ax3.barh(y_pos, [1]*len(sorted_attacks), color='salmon', height=0.5)
            ax3.set_yticks(y_pos)
            ax3.set_yticklabels(sorted_attacks) # This puts the names clearly on the left
            ax3.set_title("Vulnerability Categories Detected")
            ax3.set_xticks([]) # Hide x-axis numbers (they are meaningless for simple existence)
        else:
            ax3.text(0.5, 0.5, "No Threats Detected", ha='center', va='center')
            ax3.axis('off')

        # --- 🚨 THE MAGIC FIX ---
        # This prevents labels from being cut off and spaces charts nicely
        plt.tight_layout(rect=[0, 0.03, 1, 0.95]) 
        
        pdf.savefig(fig)
        plt.close()

    print(f"[*] Visual Report Generated: {output_path}")