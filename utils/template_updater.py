"""
Nuclei Template Updater
Keeps templates current and manages custom templates
"""
import subprocess
import sys
import os
import json
import shutil
from pathlib import Path
from datetime import datetime
from typing import Optional


class NucleiTemplateManager:
    """Manage nuclei templates - update, backup, customize"""
    
    def __init__(self, custom_templates_dir: str = None):
        self.home = Path.home()
        self.nuclei_templates_dir = self.home / "nuclei-templates"
        self.custom_templates_dir = Path(custom_templates_dir) if custom_templates_dir else Path.cwd() / "custom-templates"
        self.backup_dir = self.home / ".nuclei-backups"
        
    def check_nuclei_installed(self) -> bool:
        """Check if nuclei is installed"""
        try:
            result = subprocess.run(
                ["nuclei", "-version"],
                capture_output=True,
                text=True
            )
            return result.returncode == 0
        except FileNotFoundError:
            return False
    
    def get_template_stats(self) -> dict:
        """Get statistics about installed templates"""
        stats = {
            "total": 0,
            "by_severity": {},
            "by_type": {},
            "last_updated": None,
            "path": str(self.nuclei_templates_dir)
        }
        
        if not self.nuclei_templates_dir.exists():
            return stats
        
        # Count templates
        for tmpl in self.nuclei_templates_dir.rglob("*.yaml"):
            stats["total"] += 1
            
            # Try to categorize by folder
            rel_path = tmpl.relative_to(self.nuclei_templates_dir)
            if rel_path.parts:
                category = rel_path.parts[0]
                stats["by_type"][category] = stats["by_type"].get(category, 0) + 1
        
        # Get last modified time
        try:
            git_dir = self.nuclei_templates_dir / ".git"
            if git_dir.exists():
                result = subprocess.run(
                    ["git", "log", "-1", "--format=%ci"],
                    cwd=self.nuclei_templates_dir,
                    capture_output=True,
                    text=True
                )
                if result.returncode == 0:
                    stats["last_updated"] = result.stdout.strip()
        except Exception:
            pass
        
        return stats
    
    def update_templates(self, force: bool = False) -> dict:
        """
        Update nuclei templates to latest version.
        
        Args:
            force: Force update even if recently updated
            
        Returns:
            dict with update status and details
        """
        result = {
            "success": False,
            "message": "",
            "templates_before": 0,
            "templates_after": 0,
            "new_templates": []
        }
        
        if not self.check_nuclei_installed():
            result["message"] = "Nuclei is not installed. Install with: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
            return result
        
        # Get current count
        stats_before = self.get_template_stats()
        result["templates_before"] = stats_before["total"]
        
        print("[*] Updating nuclei templates...")
        
        try:
            # Run nuclei update
            update_result = subprocess.run(
                ["nuclei", "-update-templates"],
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            
            if update_result.returncode == 0:
                result["success"] = True
                result["message"] = "Templates updated successfully"
                
                # Get new count
                stats_after = self.get_template_stats()
                result["templates_after"] = stats_after["total"]
                
                new_count = result["templates_after"] - result["templates_before"]
                if new_count > 0:
                    result["message"] += f" (+{new_count} new templates)"
                    
                print(f"[+] {result['message']}")
                print(f"    Total templates: {result['templates_after']}")
            else:
                result["message"] = f"Update failed: {update_result.stderr}"
                print(f"[-] {result['message']}")
                
        except subprocess.TimeoutExpired:
            result["message"] = "Update timed out after 5 minutes"
            print(f"[-] {result['message']}")
        except Exception as e:
            result["message"] = f"Update error: {str(e)}"
            print(f"[-] {result['message']}")
        
        return result
    
    def backup_templates(self, backup_name: str = None) -> dict:
        """
        Create a backup of current templates.
        
        Args:
            backup_name: Custom backup name (default: timestamp)
        """
        result = {
            "success": False,
            "message": "",
            "backup_path": ""
        }
        
        if not self.nuclei_templates_dir.exists():
            result["message"] = "No templates directory found to backup"
            return result
        
        # Create backup directory
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        
        # Generate backup name
        if not backup_name:
            backup_name = datetime.now().strftime("templates_%Y%m%d_%H%M%S")
        
        backup_path = self.backup_dir / backup_name
        
        print(f"[*] Creating backup: {backup_path}")
        
        try:
            shutil.copytree(self.nuclei_templates_dir, backup_path)
            result["success"] = True
            result["message"] = f"Backup created successfully"
            result["backup_path"] = str(backup_path)
            print(f"[+] {result['message']}")
        except Exception as e:
            result["message"] = f"Backup failed: {str(e)}"
            print(f"[-] {result['message']}")
        
        return result
    
    def list_backups(self) -> list:
        """List all template backups"""
        backups = []
        
        if not self.backup_dir.exists():
            return backups
        
        for item in sorted(self.backup_dir.iterdir()):
            if item.is_dir():
                # Count templates in backup
                count = sum(1 for _ in item.rglob("*.yaml"))
                backups.append({
                    "name": item.name,
                    "path": str(item),
                    "template_count": count,
                    "created": datetime.fromtimestamp(item.stat().st_ctime).isoformat()
                })
        
        return backups
    
    def restore_backup(self, backup_name: str) -> dict:
        """Restore templates from a backup"""
        result = {
            "success": False,
            "message": ""
        }
        
        backup_path = self.backup_dir / backup_name
        
        if not backup_path.exists():
            result["message"] = f"Backup not found: {backup_name}"
            return result
        
        print(f"[*] Restoring from backup: {backup_name}")
        
        try:
            # Remove current templates
            if self.nuclei_templates_dir.exists():
                shutil.rmtree(self.nuclei_templates_dir)
            
            # Restore from backup
            shutil.copytree(backup_path, self.nuclei_templates_dir)
            
            result["success"] = True
            result["message"] = "Backup restored successfully"
            print(f"[+] {result['message']}")
        except Exception as e:
            result["message"] = f"Restore failed: {str(e)}"
            print(f"[-] {result['message']}")
        
        return result
    
    def add_custom_template(self, template_path: str, category: str = "custom") -> dict:
        """
        Add a custom template to the templates directory.
        
        Args:
            template_path: Path to custom .yaml template
            category: Category folder to place template in
        """
        result = {
            "success": False,
            "message": "",
            "destination": ""
        }
        
        template_file = Path(template_path)
        
        if not template_file.exists():
            result["message"] = f"Template file not found: {template_path}"
            return result
        
        if not template_file.suffix == ".yaml":
            result["message"] = "Template must be a .yaml file"
            return result
        
        # Create custom category in nuclei templates
        dest_dir = self.nuclei_templates_dir / category
        dest_dir.mkdir(parents=True, exist_ok=True)
        
        dest_path = dest_dir / template_file.name
        
        try:
            shutil.copy2(template_file, dest_path)
            result["success"] = True
            result["message"] = f"Template added to {category}/"
            result["destination"] = str(dest_path)
            print(f"[+] {result['message']}")
        except Exception as e:
            result["message"] = f"Failed to add template: {str(e)}"
            print(f"[-] {result['message']}")
        
        return result
    
    def search_templates(self, query: str, search_content: bool = False) -> list:
        """
        Search for templates by name or content.
        
        Args:
            query: Search query
            search_content: Also search within template files
        """
        results = []
        query_lower = query.lower()
        
        if not self.nuclei_templates_dir.exists():
            return results
        
        for tmpl in self.nuclei_templates_dir.rglob("*.yaml"):
            # Search by filename
            if query_lower in tmpl.name.lower():
                results.append({
                    "path": str(tmpl),
                    "name": tmpl.name,
                    "match_type": "filename"
                })
                continue
            
            # Search by content
            if search_content:
                try:
                    content = tmpl.read_text(encoding='utf-8', errors='ignore')
                    if query_lower in content.lower():
                        results.append({
                            "path": str(tmpl),
                            "name": tmpl.name,
                            "match_type": "content"
                        })
                except Exception:
                    pass
        
        return results[:50]  # Limit results
    
    def get_new_templates(self, days: int = 7) -> list:
        """Get templates added in the last N days"""
        new_templates = []
        
        if not self.nuclei_templates_dir.exists():
            return new_templates
        
        try:
            # Use git to find recently added templates
            result = subprocess.run(
                ["git", "log", f"--since={days} days ago", "--name-only", "--pretty=format:", "--diff-filter=A"],
                cwd=self.nuclei_templates_dir,
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                for line in result.stdout.strip().split("\n"):
                    if line.endswith(".yaml"):
                        new_templates.append(line)
        except Exception:
            pass
        
        return new_templates
    
    def print_status(self):
        """Print current template status"""
        print("\n" + "=" * 60)
        print("NUCLEI TEMPLATE STATUS")
        print("=" * 60)
        
        if not self.check_nuclei_installed():
            print("\n⚠️  Nuclei is NOT installed!")
            print("   Install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
            return
        
        stats = self.get_template_stats()
        
        print(f"\n📁 Templates Location: {stats['path']}")
        print(f"📊 Total Templates: {stats['total']}")
        print(f"🕐 Last Updated: {stats['last_updated'] or 'Unknown'}")
        
        if stats['by_type']:
            print("\n📂 Templates by Category:")
            for category, count in sorted(stats['by_type'].items(), key=lambda x: -x[1])[:15]:
                print(f"   {category}: {count}")
        
        # Show new templates
        new_templates = self.get_new_templates(7)
        if new_templates:
            print(f"\n🆕 New templates (last 7 days): {len(new_templates)}")
            for tmpl in new_templates[:5]:
                print(f"   + {tmpl}")
            if len(new_templates) > 5:
                print(f"   ... and {len(new_templates) - 5} more")
        
        # Show backups
        backups = self.list_backups()
        if backups:
            print(f"\n💾 Backups: {len(backups)}")
            for backup in backups[-3:]:
                print(f"   {backup['name']} ({backup['template_count']} templates)")


def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Nuclei Template Manager - Update, backup, and manage templates",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Show template status
  python template_updater.py --status
  
  # Update templates
  python template_updater.py --update
  
  # Create backup before updating
  python template_updater.py --backup
  python template_updater.py --update
  
  # Search for templates
  python template_updater.py --search wordpress
  python template_updater.py --search "sql injection" --content
  
  # Show new templates from last 7 days
  python template_updater.py --new
  
  # List backups
  python template_updater.py --list-backups
  
  # Restore from backup
  python template_updater.py --restore templates_20240101_120000
        """
    )
    
    parser.add_argument("--status", action="store_true", help="Show template status")
    parser.add_argument("--update", action="store_true", help="Update templates to latest")
    parser.add_argument("--backup", action="store_true", help="Create backup of current templates")
    parser.add_argument("--backup-name", help="Custom backup name")
    parser.add_argument("--restore", metavar="BACKUP", help="Restore from backup")
    parser.add_argument("--list-backups", action="store_true", help="List all backups")
    parser.add_argument("--search", metavar="QUERY", help="Search for templates")
    parser.add_argument("--content", action="store_true", help="Also search template content")
    parser.add_argument("--new", action="store_true", help="Show new templates (last 7 days)")
    parser.add_argument("--add", metavar="PATH", help="Add custom template")
    parser.add_argument("--category", default="custom", help="Category for custom template")
    
    args = parser.parse_args()
    
    manager = NucleiTemplateManager()
    
    if args.status or not any(vars(args).values()):
        manager.print_status()
    
    if args.update:
        manager.update_templates()
    
    if args.backup:
        manager.backup_templates(args.backup_name)
    
    if args.list_backups:
        backups = manager.list_backups()
        print("\n💾 Template Backups:")
        for backup in backups:
            print(f"   {backup['name']}")
            print(f"      Templates: {backup['template_count']}")
            print(f"      Created: {backup['created']}")
    
    if args.restore:
        manager.restore_backup(args.restore)
    
    if args.search:
        results = manager.search_templates(args.search, args.content)
        print(f"\n🔍 Search results for '{args.search}':")
        for r in results:
            print(f"   [{r['match_type']}] {r['name']}")
            print(f"      {r['path']}")
    
    if args.new:
        new_templates = manager.get_new_templates(7)
        print(f"\n🆕 New templates (last 7 days): {len(new_templates)}")
        for tmpl in new_templates:
            print(f"   + {tmpl}")
    
    if args.add:
        manager.add_custom_template(args.add, args.category)


if __name__ == "__main__":
    main()
