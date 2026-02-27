import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import os
import re
import threading
import queue
import json
from pathlib import Path
import time
import subprocess
import sys

from ui.licenses_window import LicensesWindow
from ui.github_update_checker import GithubUpdateChecker
import kopiaignore_editor as app_info

class IgnoreRule:
    def __init__(self, pattern):
        self.pattern = pattern.strip()
        self.is_negation = self.pattern.startswith('!')
        if self.is_negation:
            clean = self.pattern[1:]
        else:
            clean = self.pattern
        
        # Handle escaped !
        if clean.startswith('\\!'):
            clean = clean[1:]
            
        # Strip trailing spaces
        clean = clean.rstrip()
        
        self.is_dir_only = clean.endswith('/')
        if self.is_dir_only:
            clean = clean[:-1]
            
        self.regex = self._compile_regex(clean)

    def _compile_regex(self, pat):
        # Convert gitignore pattern to regex
        res = ""
        
        # Check for / (not at end, which was already stripped)
        has_slash = '/' in pat
        
        if pat.startswith('/'):
            # Absolute path relative to .kopiaignore location
            res += r"^"
            pat = pat[1:]
        elif pat.startswith('**/'):
            # Starts with double star
            res += r"(?:^|/)" # Matches start or after a slash
            pat = pat[3:] # Remove **/
        elif has_slash:
            # Has slash in middle, anchor to root
            res += r"^"
        else:
            # No slash, match anywhere
            res += r"(?:^|/)"

        # Process characters
        i = 0
        n = len(pat)
        while i < n:
            c = pat[i]
            if c == '*':
                if i + 1 < n and pat[i+1] == '*':
                    # **
                    if i + 2 < n and pat[i+2] == '/':
                        # **/
                        res += r"(?:.*/)?"
                        i += 3
                    else:
                        # ** at end
                        res += r".*"
                        i += 2
                else:
                    # *
                    res += r"[^/]*"
                    i += 1
            elif c == '?':
                res += r"[^/]"
                i += 1
            elif c == '[':
                # Character class - simplified handling
                j = i
                while j < n and pat[j] != ']':
                    j += 1
                if j < n:
                    res += pat[i:j+1]
                    i = j + 1
                else:
                    res += re.escape(c)
                    i += 1
            elif c in '.+()|^${}':
                res += re.escape(c)
                i += 1
            else:
                res += c
                i += 1
        
        res += r"$"
        return re.compile(res)

    def matches(self, rel_path, is_dir):
        # rel_path must be relative to root and use forward slashes
        if self.is_dir_only and not is_dir:
            return False
        return self.regex.search(rel_path) is not None

class KopiaIgnore:
    def __init__(self, root_dir):
        self.root_dir = root_dir
        self.rules = []
        self.content = ""
        self.original_content = ""
        self.load()

    def load(self):
        path = os.path.join(self.root_dir, '.kopiaignore')
        self.rules = []
        if os.path.exists(path):
            with open(path, 'r', encoding='utf-8') as f:
                self.content = f.read()
            self._parse_content()
        else:
            self.content = ""
        self.original_content = self.content

    def _parse_content(self):
        self.rules = []
        for line in self.content.splitlines():
            s = line.strip()
            if not s or s.startswith('#'):
                continue
            self.rules.append(IgnoreRule(s))

    def update_content(self, new_content):
        self.content = new_content
        self._parse_content()

    def save(self):
        path = os.path.join(self.root_dir, '.kopiaignore')
        with open(path, 'w', encoding='utf-8') as f:
            f.write(self.content)
            if self.content and not self.content.endswith('\n'):
                f.write('\n')
        self.original_content = self.content

    def is_ignored(self, rel_path, is_dir):
        # Last match wins
        ignored = False
        for rule in self.rules:
            if rule.matches(rel_path, is_dir):
                ignored = not rule.is_negation
        return ignored

class FileNode:
    def __init__(self, name, is_dir, rel_path):
        self.name = name
        self.is_dir = is_dir
        self.rel_path = rel_path.replace('\\', '/')
        self.children = []
        self.ignored = False
        self.size = 0
        self.cumulative_size = 0
        self.included_cumulative_size = 0

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"KopiaIgnore Editor v{app_info.APP_VERSION}")
        self.geometry("1200x800")
        
        self.root_dir = None
        self.kopia_ignore = None
        self.root_node = None
        self.scan_queue = queue.Queue()
        self.access_errors = []
        self.licenses_window = None
        self.update_checker = None
        
        self.scan_progress = 0
        self.sim_progress = 0
        self.scanning = False
        self.simulating = False
        self.in_reload_sequence = False
        self.scan_start_time = 0
        self.scan_duration = 0
        self.sim_start_time = 0
        self.current_sim_factor = 0.1
        self.sim_queue = queue.Queue()
        
        if os.name == 'nt':
            self.config_dir = Path(os.environ['LOCALAPPDATA']) / "py_apps" / "kopia_ignore_editor"
        else:
            self.config_dir = Path.home() / ".config" / "kopia_ignore_editor"
        self.recent_dirs_file = self.config_dir / "recent.json"
        self.stats_file = self.config_dir / "stats.json"
        self.recent_dirs = []
        self.max_recent = 10
        self.dir_stats = {}
        
        self._setup_ui()
        
        self._load_recent_dirs()
        self._load_stats()
        
        # Start in current dir or ask
        self.protocol("WM_DELETE_WINDOW", self.on_closing)
        initial_dir = os.getcwd()
        if os.path.exists(os.path.join(initial_dir, ".kopiaignore")):
            self._add_to_recent(initial_dir)
            self.load_directory(initial_dir)
        
        self.update_admin_status()

        self.lift()
        self.grab_set()
        self.attributes('-topmost', True)
        self.after_idle(self.attributes, '-topmost', False)
        self.focus_force()

        try:
            self.update_checker = GithubUpdateChecker(
                github_id=app_info.APP_GITHUB_ID,
                app_name=app_info.APPNAME,
                current_version=app_info.APP_VERSION,
                root=self
            )
        except Exception as e:
            print(f"Failed to initialize update checker: {e}")

    def _setup_ui(self):
        # Toolbar
        toolbar = ttk.Frame(self, padding=5)
        toolbar.pack(fill=tk.X)
        
        ttk.Button(toolbar, text="Open Directory", command=self.choose_directory).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="Reload Scan", command=self.reload_scan).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="Save .kopiaignore", command=self.save_ignore).pack(side=tk.LEFT, padx=2)
        
        self.recent_menu_button = ttk.Menubutton(toolbar, text="Recent")
        self.recent_menu = tk.Menu(self.recent_menu_button, tearoff=0)
        self.recent_menu_button["menu"] = self.recent_menu
        self.recent_menu_button.pack(side=tk.LEFT, padx=2)

        ttk.Button(toolbar, text="Licenses", command=self.show_licenses_window).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="Check for Updates", command=self.check_for_updates).pack(side=tk.LEFT, padx=2)
        
        self.error_button = ttk.Button(toolbar, text="Ignore Errors", command=self.fix_access_errors)
        
        if os.name == 'nt':
            self.admin_button = ttk.Button(toolbar, text="Restart as Administrator", command=self.run_as_admin)
            self.admin_button.pack(side=tk.RIGHT, padx=5)
        
        self.status_var = tk.StringVar(value="Ready")
        
        # Main Paned Window
        paned = ttk.PanedWindow(self, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Left: Treeview
        tree_frame = ttk.Frame(paned)
        paned.add(tree_frame, weight=1)
        
        self.tree = ttk.Treeview(tree_frame, columns=("Size", "Included Size", "Status"), selectmode="browse")
        self.tree.heading("#0", text="Path", command=lambda: self.sort_tree_by_column("#0", False))
        self.tree.heading("Size", text="Total Size (MB)", command=lambda: self.sort_tree_by_column("Size", True))
        self.tree.column("Size", width=100, anchor="e")
        self.tree.heading("Included Size", text="Included (MB)", command=lambda: self.sort_tree_by_column("Included Size", True))
        self.tree.column("Included Size", width=100, anchor="e")
        self.tree.heading("Status", text="Status")
        self.tree.column("Status", width=100, anchor="center")
        
        scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Treeview Tags
        self.tree.tag_configure("ignored", foreground="gray", font=("Segoe UI", 9, "italic"))
        self.tree.tag_configure("included", foreground="black")
        
        # Context Menu
        self.context_menu = tk.Menu(self, tearoff=0)
        self.tree.bind("<Button-3>", self.show_context_menu)
        
        # Right: Editor
        editor_frame = ttk.Frame(paned)
        paned.add(editor_frame, weight=1)
        
        lbl = ttk.Label(editor_frame, text=".kopiaignore content:")
        lbl.pack(anchor="w")
        
        self.editor = scrolledtext.ScrolledText(editor_frame, font=("Consolas", 10))
        self.editor.pack(fill=tk.BOTH, expand=True)
        self.editor.bind("<<Modified>>", self.on_editor_change)
        self.editor.bind("<KeyRelease>", self.on_editor_change)
        
        # Apply Button (Manual)
        ttk.Button(editor_frame, text="Simulate / Apply Changes", command=self.apply_changes).pack(fill=tk.X, pady=5)

        # Status Bar
        status_frame = ttk.Frame(self, relief=tk.SUNKEN)
        status_frame.pack(fill=tk.X, side=tk.BOTTOM)

        self.progress_bar = ttk.Progressbar(status_frame, orient=tk.HORIZONTAL, length=200)

        status_bar = ttk.Label(status_frame, textvariable=self.status_var, anchor=tk.W)
        status_bar.pack(fill=tk.X, side=tk.LEFT, expand=True, padx=5)

        self.ignored_size_var = tk.StringVar()
        ignored_label = ttk.Label(status_frame, textvariable=self.ignored_size_var, anchor=tk.E)
        ignored_label.pack(side=tk.RIGHT, padx=5)

        self.included_size_var = tk.StringVar()
        included_label = ttk.Label(status_frame, textvariable=self.included_size_var, anchor=tk.E)
        included_label.pack(side=tk.RIGHT, padx=5)

    def choose_directory(self):
        if not self.check_save_changes(): return
        d = filedialog.askdirectory()
        if d:
            self._add_to_recent(d)
            self.load_directory(d)

    def check_for_updates(self):
        if self.update_checker:
            self.update_checker.check_now_interactive(self)

    def show_licenses_window(self):
        if self.licenses_window and self.licenses_window.winfo_exists():
            self.licenses_window.lift()
            self.licenses_window.focus_force() # type: ignore
            return
        self.licenses_window = LicensesWindow(self)

    def load_directory(self, path):
        self.root_dir = path
        self.title(f"KopiaIgnore Editor v{app_info.APP_VERSION} - {path}")
        self.kopia_ignore = KopiaIgnore(path)
        self.editor.delete("1.0", tk.END)
        self.editor.insert("1.0", self.kopia_ignore.content)
        self.editor.edit_modified(False)
        
        self.reload_scan()

    def _calculate_cumulative_sizes(self, node):
        if not node.is_dir:
            node.cumulative_size = node.size
            return node.size

        total_size = 0
        for child in node.children:
            total_size += self._calculate_cumulative_sizes(child)
        
        node.cumulative_size = total_size
        return total_size

    def _calculate_included_sizes(self, node):
        if not node.is_dir:
            node.included_cumulative_size = node.size if not node.ignored else 0
            return node.included_cumulative_size

        total_included_size = 0
        for child in node.children:
            total_included_size += self._calculate_included_sizes(child)
        
        node.included_cumulative_size = total_included_size
        return total_included_size

    def sort_tree_by_column(self, col, reverse):
        if not self.root_node:
            return

        if col == "#0":
            key_func = lambda node: node.name.lower()
        elif col == "Size":
            key_func = lambda node: node.cumulative_size
        elif col == "Included Size":
            key_func = lambda node: node.included_cumulative_size
        else:
            return

        self._sort_node_children(self.root_node, key_func, reverse)
        self._populate_tree()
        self.tree.heading(col, command=lambda: self.sort_tree_by_column(col, not reverse))

    def _sort_node_children(self, node, key_func, reverse):
        if node and node.is_dir:
            node.children.sort(key=key_func, reverse=reverse)
            for child in node.children:
                self._sort_node_children(child, key_func, reverse)

    def reload_scan(self):
        if not self.root_dir: return
        if self.scanning or self.simulating: return
        
        self.status_var.set("Scanning directory...")
        self.tree.delete(*self.tree.get_children())
        
        self.scan_progress = 0
        self.scanning = True
        self.in_reload_sequence = True
        self.scan_start_time = time.time()
        
        total_estimate = self.dir_stats.get(os.path.abspath(self.root_dir))
        if total_estimate:
            count = total_estimate.get('count', 0) if isinstance(total_estimate, dict) else total_estimate
            self.current_sim_factor = total_estimate.get('sim_factor', 0.1) if isinstance(total_estimate, dict) else 0.1
            total_max = count * (1 + self.current_sim_factor)
            self.progress_bar.config(mode='determinate', maximum=total_max, value=0)
            self.progress_bar.pack(side=tk.RIGHT, padx=5)
        else:
            self.progress_bar.pack_forget()
            self.current_sim_factor = 0.1
        
        # Run scan in thread
        threading.Thread(target=self._scan_thread, args=(self.root_dir,), daemon=True).start()
        self.after(100, self._check_scan_queue)
        self.after(200, self._update_progress)

    def _scan_thread(self, root_path):
        try:
            # Build tree in memory
            root_node = FileNode(os.path.basename(root_path), True, "")
            
            # Map path -> node for quick parent lookup
            # We use rel_path as key
            nodes = {"": root_node}
            
            access_errors = []
            
            def on_walk_error(e):
                if e.filename:
                    access_errors.append(e.filename)
            
            count = 1
            self.scan_progress = count
            
            for root, dirs, files in os.walk(root_path, onerror=on_walk_error):
                count += len(dirs) + len(files)
                self.scan_progress = count
                
                rel_base = os.path.relpath(root, root_path)
                if rel_base == ".": rel_base = ""
                
                parent_node = nodes.get(rel_base.replace('\\', '/'))
                if not parent_node: continue # Should not happen if walk is top-down
                
                # Process dirs
                for d in dirs:
                    rel = os.path.join(rel_base, d).replace('\\', '/')
                    node = FileNode(d, True, rel)
                    parent_node.children.append(node)
                    nodes[rel] = node
                
                # Process files
                for f in files:
                    rel = os.path.join(rel_base, f).replace('\\', '/')
                    node = FileNode(f, False, rel)
                    try:
                        node.size = os.path.getsize(os.path.join(root, f))
                    except OSError:
                        node.size = 0
                        access_errors.append(os.path.join(root, f))
                    parent_node.children.append(node)
            
            self._calculate_cumulative_sizes(root_node)
            self.scan_queue.put((root_node, access_errors))
        except Exception as e:
            self.scan_queue.put(e)

    def _check_scan_queue(self):
        try:
            item = self.scan_queue.get_nowait()
            if isinstance(item, Exception):
                messagebox.showerror("Error", str(item))
                self.status_var.set("Scan failed.")
                self.scanning = False
                self.in_reload_sequence = False
                self.progress_bar.pack_forget()
            elif isinstance(item, tuple):
                self.scan_duration = time.time() - self.scan_start_time
                self.scanning = False
                
                self.root_node, self.access_errors = item
                
                if self.in_reload_sequence:
                    total_max = self.scan_progress * (1 + self.current_sim_factor)
                    self.progress_bar.config(maximum=total_max)
                
                self.status_var.set("Scan complete. Rendering tree...")
                self.apply_changes() # Calculate ignored status
                
                if self.access_errors:
                    self.error_button.config(text=f"Ignore {len(self.access_errors)} Access Errors")
                    self.error_button.pack(side=tk.LEFT, padx=2)
                else:
                    self.error_button.pack_forget()
            else:
                self.after(100, self._check_scan_queue)
        except queue.Empty:
            self.after(100, self._check_scan_queue)

    def _populate_tree(self):
        self.tree.delete(*self.tree.get_children())
        if not self.root_node: return
        
        # We use a lazy loading approach for the treeview to keep it responsive
        # But we have the full tree in memory.
        
        # Insert root children
        self._insert_node("", self.root_node)

    def _insert_node(self, parent_id, node):
        # Determine tag
        tag = "ignored" if node.ignored else "included"
        status_text = "Ignored" if node.ignored else ""
        
        size_mb = node.cumulative_size / (1024 * 1024)
        size_text = f"{size_mb:.2f}" if size_mb > 0.01 else ""
        
        included_size_mb = node.included_cumulative_size / (1024 * 1024)
        included_size_text = f"{included_size_mb:.2f}" if included_size_mb > 0.01 else ""
        
        # Insert item
        # We store the node object in values or we map id to node?
        # Let's map id to node using a dictionary if needed, but for now just path
        
        # Note: Treeview items need unique IDs. We can use rel_path.
        # Root is empty string rel_path, but treeview root is empty string parent.
        
        # Actually, let's just recurse for the first level and add dummy for children
        # to support lazy loading if the tree is huge.
        # For now, let's try full population but optimized.
        
        # To avoid freezing UI on huge trees, we only populate visible nodes?
        # Let's populate recursively.
        
        item_id = self.tree.insert(parent_id, "end", text=node.name, values=(size_text, included_size_text, status_text), tags=(tag,), open=True if not parent_id else False)
        
        # Store node reference
        self.tree.item(item_id, tags=(tag, node.rel_path)) # Store rel_path in tags for retrieval
        
        for child in node.children:
            self._insert_node(item_id, child)

    def apply_changes(self):
        if self.simulating: return

        # Get content from editor
        content = self.editor.get("1.0", tk.END)
        assert self.kopia_ignore is not None
        self.kopia_ignore.update_content(content)
        self.editor.edit_modified(False)
        
        # Re-evaluate tree
        if self.root_node:
            self.status_var.set("Simulating...")
            self.simulating = True
            self.sim_progress = 0
            self.sim_start_time = time.time()
            
            if not self.in_reload_sequence:
                # Manual apply
                self.progress_bar.config(mode='determinate', maximum=self.scan_progress, value=0)
                self.progress_bar.pack(side=tk.RIGHT, padx=5)
                self.after(200, self._update_progress)
            
            self.update_idletasks()
            
            threading.Thread(target=self._simulation_thread, daemon=True).start()
            self.after(100, self._check_sim_queue)

    def _simulation_thread(self):
        try:
            self._evaluate_node(self.root_node)
            self._calculate_included_sizes(self.root_node)
            self.sim_queue.put("done")
        except Exception as e:
            self.sim_queue.put(e)

    def _check_sim_queue(self):
        try:
            item = self.sim_queue.get_nowait()
            if item == "done":
                self._on_simulation_complete()
            elif isinstance(item, Exception):
                messagebox.showerror("Error", str(item))
                self.simulating = False
                self.in_reload_sequence = False
                self.progress_bar.pack_forget()
                self.status_var.set("Simulation failed.")
            else:
                self.after(100, self._check_sim_queue)
        except queue.Empty:
            self.after(100, self._check_sim_queue)

    def _on_simulation_complete(self):
        sim_duration = time.time() - self.sim_start_time
        self.simulating = False
        
        if self.in_reload_sequence:
            if self.scan_duration > 0:
                self.current_sim_factor = sim_duration / self.scan_duration
            
            assert self.root_dir is not None
            abs_path = os.path.abspath(self.root_dir)
            self.dir_stats[abs_path] = {
                "count": self.scan_progress,
                "sim_factor": self.current_sim_factor
            }
            self._save_stats()
            self.in_reload_sequence = False
            
            self.sort_tree_by_column("Included Size", True)
        else:
            self._refresh_tree_visuals()
            
        self._update_summary_stats()
        self.status_var.set(f"Loaded {self.root_dir}")
        self.progress_bar.pack_forget()

    def _evaluate_node(self, node, parent_ignored=False):
        self.sim_progress += 1
        # This function recursively determines the ignore status of a node and its children.
        if node.rel_path == "":
            # Root is never ignored.
            node.ignored = False
        else:
            # Find the last rule in .kopiaignore that matches this specific path.
            last_matching_rule = None
            assert self.kopia_ignore is not None
            for rule in self.kopia_ignore.rules:
                if rule.matches(node.rel_path, node.is_dir):
                    last_matching_rule = rule

            # The logic for deciding ignore status, from most to least important:
            # 1. An explicit negation ('!pattern') on this path makes it included.
            # 2. If the parent is ignored, this path is also ignored (unless explicitly re-included).
            # 3. An explicit ignore ('pattern') on this path makes it ignored.
            # 4. Otherwise, it's included.
            if last_matching_rule and last_matching_rule.is_negation:
                node.ignored = False
            elif parent_ignored:
                node.ignored = True
            else:
                node.ignored = self.kopia_ignore.is_ignored(node.rel_path, node.is_dir)

        # Recurse into children, passing down the determined ignore status of the current node.
        for child in node.children:
            self._evaluate_node(child, node.ignored)

    def _refresh_tree_visuals(self):
        if not self.root_node: return
        
        roots = self.tree.get_children()
        if not roots:
            self._populate_tree()
            return
            
        self._update_item_recursive(roots[0], self.root_node)

    def _update_item_recursive(self, item_id, node):
        tag = "ignored" if node.ignored else "included"
        status_text = "Ignored" if node.ignored else ""
        
        # Update values if changed
        current_values = self.tree.item(item_id, "values")
        if current_values:
            size_text = current_values[0]
            
            included_size_mb = node.included_cumulative_size / (1024 * 1024)
            included_size_text = f"{included_size_mb:.2f}" if included_size_mb > 0.01 else ""
            
            current_included_text = current_values[1] if len(current_values) > 1 else ""
            current_status = current_values[2] if len(current_values) > 2 else ""
            
            if current_status != status_text or current_included_text != included_size_text:
                self.tree.item(item_id, values=(size_text, included_size_text, status_text))
        
        # Update tags
        self.tree.item(item_id, tags=(tag, node.rel_path))
            
        # Recurse
        children_ids = self.tree.get_children(item_id)
        if len(children_ids) == len(node.children):
            for i, child_node in enumerate(node.children):                self._update_item_recursive(children_ids[i], child_node)

    def _update_summary_stats(self):
        if not self.root_node:
            self.included_size_var.set("")
            self.ignored_size_var.set("")
            return

        included_size = 0
        ignored_size = 0

        nodes_to_visit = [self.root_node]
        while nodes_to_visit:
            node = nodes_to_visit.pop(0)
            if not node.is_dir:
                if node.ignored:
                    ignored_size += node.size
                else:
                    included_size += node.size
            
            if node.is_dir:
                nodes_to_visit.extend(node.children)

        included_mb = included_size / (1024 * 1024)
        ignored_mb = ignored_size / (1024 * 1024)
        self.included_size_var.set(f"Included: {included_mb:.2f} MB")
        self.ignored_size_var.set(f"Ignored: {ignored_mb:.2f} MB")

    def _update_progress(self):
        if not (self.scanning or self.simulating): return
        
        if self.progress_bar.winfo_ismapped():
            val = 0
            if self.scanning:
                val = self.scan_progress
                max_val = int(self.progress_bar['maximum'])
                self.status_var.set(f"Scanning... {val} / {max_val}")
            elif self.simulating:
                val = self.sim_progress
                self.status_var.set(f"Simulating... {val}")
                
                if self.in_reload_sequence:
                    val = self.scan_progress + (self.sim_progress * self.current_sim_factor)
                
            self.progress_bar['value'] = val
        
        self.after(200, self._update_progress)

    def _load_recent_dirs(self):
        if self.recent_dirs_file.exists():
            try:
                with open(self.recent_dirs_file, 'r') as f:
                    self.recent_dirs = json.load(f)
            except (json.JSONDecodeError, IOError):
                self.recent_dirs = []
        self._update_recent_menu()

    def _save_recent_dirs(self):
        try:
            self.config_dir.mkdir(parents=True, exist_ok=True)
            with open(self.recent_dirs_file, 'w') as f:
                json.dump(self.recent_dirs, f, indent=4)
        except IOError:
            pass

    def _update_recent_menu(self):
        self.recent_menu.delete(0, tk.END)
        for path in self.recent_dirs:
            self.recent_menu.add_command(label=path, command=lambda p=path: self.load_directory(p))

    def _load_stats(self):
        if self.stats_file.exists():
            try:
                with open(self.stats_file, 'r') as f:
                    raw_stats = json.load(f)
                    self.dir_stats = {}
                    for k, v in raw_stats.items():
                        if isinstance(v, int):
                            self.dir_stats[k] = {"count": v, "sim_factor": 0.1}
                        else:
                            self.dir_stats[k] = v
            except:
                self.dir_stats = {}

    def _save_stats(self):
        try:
            self.config_dir.mkdir(parents=True, exist_ok=True)
            with open(self.stats_file, 'w') as f:
                json.dump(self.dir_stats, f, indent=4)
        except:
            pass

    def save_ignore(self):
        content = self.editor.get("1.0", tk.END)
        assert self.kopia_ignore is not None
        self.kopia_ignore.update_content(content)
        self.kopia_ignore.save()
        self.on_editor_change()
        messagebox.showinfo("Saved", ".kopiaignore saved successfully.")

    def open_in_explorer(self, path):
        try:
            if os.name == 'nt':
                os.startfile(path)
            elif sys.platform == 'darwin':
                subprocess.call(['open', path])
            else:
                subprocess.call(['xdg-open', path])
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open explorer: {e}")

    def show_context_menu(self, event):
        item_id = self.tree.identify_row(event.y)
        if not item_id: return
        
        self.tree.selection_set(item_id)
        tags = self.tree.item(item_id, "tags")
        rel_path = tags[-1]
        name = self.tree.item(item_id, "text")
        
        menu = tk.Menu(self, tearoff=0)
        
        assert self.root_dir is not None
        full_path = os.path.normpath(os.path.join(self.root_dir, rel_path))
        if os.path.isdir(full_path):
            menu.add_command(label="Open as Root", command=lambda: self.open_as_root(full_path))
            menu.add_command(label="Open in Explorer", command=lambda: self.open_in_explorer(full_path))
            menu.add_separator()
        
        menu.add_command(label=f"Ignore '/{rel_path}'", command=lambda: self.add_rule(f"/{rel_path}"))
        menu.add_command(label=f"Ignore Name '{name}'", command=lambda: self.add_rule(f"{name}"))
        
        if "." in name:
            ext = name.split(".")[-1]
            menu.add_command(label=f"Ignore Extension '*.{ext}'", command=lambda: self.add_rule(f"*.{ext}"))
            
        menu.add_separator()
        menu.add_command(label=f"Include (Exception) '!/{rel_path}'", command=lambda: self.add_rule(f"!/{rel_path}"))
        
        menu.post(event.x_root, event.y_root)

    def open_as_root(self, path):
        if self.check_save_changes():
            self._add_to_recent(path)
            self.load_directory(path)

    def add_rule(self, rule):
        # Append to editor
        current_content = self.editor.get("1.0", tk.END).rstrip()
        if current_content:
            new_content = current_content + "\n" + rule + "\n"
        else:
            new_content = rule + "\n"
            
        self.editor.delete("1.0", tk.END)
        self.editor.insert("1.0", new_content)

    def _add_to_recent(self, path):
        if path in self.recent_dirs:
            self.recent_dirs.remove(path)
        self.recent_dirs.insert(0, path)
        self.recent_dirs = self.recent_dirs[:self.max_recent]
        self._save_recent_dirs()
        self._update_recent_menu()

    def fix_access_errors(self):
        if not self.access_errors: return
        
        new_rules = []
        for path in self.access_errors:
            try:
                rel = os.path.relpath(path, self.root_dir)
                rel = rel.replace('\\', '/')
                new_rules.append(f"/{rel}")
            except ValueError:
                pass
        
        if not new_rules: return
        
        current_content = self.editor.get("1.0", tk.END).rstrip()
        to_add = "\n# Ignored due to access errors:\n" + "\n".join(new_rules)
        
        if current_content:
            new_content = current_content + "\n" + to_add + "\n"
        else:
            new_content = to_add + "\n"
            
        self.editor.delete("1.0", tk.END)
        self.editor.insert("1.0", new_content)
        
        self.access_errors = []
        self.error_button.pack_forget()
        messagebox.showinfo("Updated", f"Added {len(new_rules)} rules for inaccessible files/directories.")

    def is_admin(self):
        if os.name == 'nt':
            try:
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            except:
                return False
        return False

    def run_as_admin(self):
        if os.name == 'nt':
            try:
                import ctypes
                import sys
                
                executable = sys.executable
                # Attempt to use pythonw.exe to avoid console window
                if executable.lower().endswith('python.exe'):
                    w_executable = executable[:-4] + 'w.exe'
                    if os.path.exists(w_executable):
                        executable = w_executable

                ctypes.windll.shell32.ShellExecuteW(
                    None,
                    "runas",
                    executable,
                    f'"{os.path.abspath(sys.argv[0])}"', # Pass the script path, quoted
                    None,
                    1
                )
                self.destroy()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to elevate privileges: {e}")

    def update_admin_status(self):
        if os.name == 'nt' and self.is_admin():
            self.title(self.title() + " (Administrator)")
            if hasattr(self, 'admin_button'):
                self.admin_button.pack_forget()

    def on_editor_change(self, event=None):
        if self.editor.edit_modified():
            self.editor.edit_modified(False)
        
        if self.has_unsaved_changes():
            if not self.title().endswith(" *"):
                self.title(self.title() + " *")
        else:
            if self.title().endswith(" *"):
                self.title(self.title()[:-2])

    def has_unsaved_changes(self):
        if not self.kopia_ignore: return False
        curr = self.editor.get("1.0", tk.END).strip()
        orig = self.kopia_ignore.original_content.strip()
        return curr != orig

    def check_save_changes(self):
        if self.has_unsaved_changes():
            resp = messagebox.askyesnocancel("Unsaved Changes", "You have unsaved changes. Save before continuing?")
            if resp is None: return False
            if resp:
                self.save_ignore()
                return True
            return True
        return True

    def on_closing(self):
        if self.check_save_changes():
            self.destroy()

if __name__ == "__main__":
    app = App()
    app.mainloop()