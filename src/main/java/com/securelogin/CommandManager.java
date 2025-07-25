package com.securelogin;

import org.bukkit.Bukkit;
import org.bukkit.ChatColor;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.entity.Player;

import java.util.UUID;

public class CommandManager implements CommandExecutor {
    private final SecureLogin plugin;
    
    public CommandManager(SecureLogin plugin) {
        this.plugin = plugin;
    }
    
    @Override
    public boolean onCommand(CommandSender sender, Command command, String label, String[] args) {
        String cmd = command.getName().toLowerCase();
        
        switch (cmd) {
            case "register":
                return handleRegister(sender, args);
            case "login":
                return handleLogin(sender, args);
            case "logout":
                return handleLogout(sender, args);
            case "changepassword":
                return handleChangePassword(sender, args);
            case "unregister":
                return handleUnregister(sender, args);
            case "loginadmin":
                return handleAdmin(sender, args);
            default:
                return false;
        }
    }
    
    // ========== REGISTER COMMAND ==========
    
    private boolean handleRegister(CommandSender sender, String[] args) {
        if (!(sender instanceof Player)) {
            sender.sendMessage(ChatColor.RED + "This command can only be used by players.");
            return true;
        }
        
        Player player = (Player) sender;
        
        // Check if player is already registered
        if (plugin.isRegistered(player.getUniqueId())) {
            player.sendMessage(ChatColor.RED + plugin.getMessage("already-registered"));
            return true;
        }
        
        // Check if player is already logged in
        if (plugin.isLoggedIn(player.getUniqueId())) {
            player.sendMessage(ChatColor.RED + plugin.getMessage("already-logged-in"));
            return true;
        }
        
        // Check arguments
        if (args.length != 1) {
            player.sendMessage(ChatColor.RED + plugin.getMessage("register-usage"));
            return true;
        }
        
        String password = args[0];
        
        // Validate password
        int minPasswordLength = plugin.getConfig().getInt("security.min-password-length", 4);
        if (password.length() < minPasswordLength) {
            player.sendMessage(ChatColor.RED + plugin.getMessage("password-too-short")
                    .replace("%min%", String.valueOf(minPasswordLength)));
            return true;
        }
        
        // Register user
        if (plugin.registerUser(player.getUniqueId(), password)) {
            plugin.setLoggedIn(player, true);
            player.sendMessage(ChatColor.GREEN + plugin.getMessage("register-success"));
        } else {
            player.sendMessage(ChatColor.RED + plugin.getMessage("register-fail"));
        }
        
        return true;
    }
    
    // ========== LOGIN COMMAND ==========
    
    private boolean handleLogin(CommandSender sender, String[] args) {
        if (!(sender instanceof Player)) {
            sender.sendMessage(ChatColor.RED + "This command can only be used by players.");
            return true;
        }
        
        Player player = (Player) sender;
        
        // Check if player is already logged in
        if (plugin.isLoggedIn(player.getUniqueId())) {
            player.sendMessage(ChatColor.RED + plugin.getMessage("already-logged-in"));
            return true;
        }
        
        // Check if player is registered
        if (!plugin.isRegistered(player.getUniqueId())) {
            player.sendMessage(ChatColor.RED + plugin.getMessage("not-registered"));
            return true;
        }
        
        // Check arguments
        if (args.length != 1) {
            player.sendMessage(ChatColor.RED + plugin.getMessage("login-usage"));
            return true;
        }
        
        String password = args[0];
        
        // Check password
        if (plugin.checkPassword(player.getUniqueId(), password)) {
            plugin.setLoggedIn(player, true);
            player.sendMessage(ChatColor.GREEN + plugin.getMessage("login-success"));
        } else {
            // Increment login attempts
            int attempts = plugin.incrementLoginAttempt(player.getUniqueId());
            int maxAttempts = plugin.getConfig().getInt("security.max-login-attempts", 5);
            
            if (attempts >= maxAttempts) {
                // Check kick or ban
                boolean ban = plugin.getConfig().getBoolean("security.ban-on-max-attempts", false);
                
                if (ban) {
                    player.kickPlayer(ChatColor.RED + plugin.getMessage("banned-too-many-attempts"));
                    String banTime = plugin.getConfig().getString("security.ban-time", "1h");
                    // Implement ban logic here (requires a ban management system)
                } else {
                    player.kickPlayer(ChatColor.RED + plugin.getMessage("kicked-too-many-attempts"));
                }
            } else {
                player.sendMessage(ChatColor.RED + plugin.getMessage("login-fail")
                        .replace("%attempts%", String.valueOf(attempts))
                        .replace("%max%", String.valueOf(maxAttempts)));
            }
        }
        
        return true;
    }
    
    // ========== LOGOUT COMMAND ==========
    
    private boolean handleLogout(CommandSender sender, String[] args) {
        if (!(sender instanceof Player)) {
            sender.sendMessage(ChatColor.RED + "This command can only be used by players.");
            return true;
        }
        
        Player player = (Player) sender;
        
        // Check if player is logged in
        if (!plugin.isLoggedIn(player.getUniqueId())) {
            player.sendMessage(ChatColor.RED + plugin.getMessage("not-logged-in"));
            return true;
        }
        
        // Log player out
        plugin.setLoggedIn(player, false);
        player.sendMessage(ChatColor.GREEN + plugin.getMessage("logout-success"));
        
        return true;
    }
    
    // ========== CHANGE PASSWORD COMMAND ==========
    
    private boolean handleChangePassword(CommandSender sender, String[] args) {
        if (!(sender instanceof Player)) {
            sender.sendMessage(ChatColor.RED + "This command can only be used by players.");
            return true;
        }
        
        Player player = (Player) sender;
        
        // Check if player is logged in
        if (!plugin.isLoggedIn(player.getUniqueId())) {
            player.sendMessage(ChatColor.RED + plugin.getMessage("not-logged-in"));
            return true;
        }
        
        // Check arguments
        if (args.length != 2) {
            player.sendMessage(ChatColor.RED + plugin.getMessage("changepass-usage"));
            return true;
        }
        
        String oldPassword = args[0];
        String newPassword = args[1];
        
        // Validate old password
        if (!plugin.checkPassword(player.getUniqueId(), oldPassword)) {
            player.sendMessage(ChatColor.RED + plugin.getMessage("old-password-wrong"));
            return true;
        }
        
        // Validate new password
        int minPasswordLength = plugin.getConfig().getInt("security.min-password-length", 4);
        if (newPassword.length() < minPasswordLength) {
            player.sendMessage(ChatColor.RED + plugin.getMessage("password-too-short")
                    .replace("%min%", String.valueOf(minPasswordLength)));
            return true;
        }
        
        // Change password
        if (plugin.changePassword(player.getUniqueId(), newPassword)) {
            player.sendMessage(ChatColor.GREEN + plugin.getMessage("changepass-success"));
        } else {
            player.sendMessage(ChatColor.RED + plugin.getMessage("changepass-fail"));
        }
        
        return true;
    }
    
    // ========== UNREGISTER COMMAND ==========
    
    private boolean handleUnregister(CommandSender sender, String[] args) {
        if (!(sender instanceof Player)) {
            sender.sendMessage(ChatColor.RED + "This command can only be used by players.");
            return true;
        }
        
        Player player = (Player) sender;
        
        // Check if unregistration is allowed
        if (!plugin.getConfig().getBoolean("general.allow-unregister", true)) {
            player.sendMessage(ChatColor.RED + plugin.getMessage("unregister-disabled"));
            return true;
        }
        
        // Check if player is logged in
        if (!plugin.isLoggedIn(player.getUniqueId())) {
            player.sendMessage(ChatColor.RED + plugin.getMessage("not-logged-in"));
            return true;
        }
        
        // Check arguments
        if (args.length != 1) {
            player.sendMessage(ChatColor.RED + plugin.getMessage("unregister-usage"));
            return true;
        }
        
        String password = args[0];
        
        // Validate password
        if (!plugin.checkPassword(player.getUniqueId(), password)) {
            player.sendMessage(ChatColor.RED + plugin.getMessage("unregister-wrong-password"));
            return true;
        }
        
        // Unregister user
        if (plugin.unregisterUser(player.getUniqueId())) {
            plugin.setLoggedIn(player, false);
            player.sendMessage(ChatColor.GREEN + plugin.getMessage("unregister-success"));
        } else {
            player.sendMessage(ChatColor.RED + plugin.getMessage("unregister-fail"));
        }
        
        return true;
    }
    
    // ========== ADMIN COMMANDS ==========
    
    private boolean handleAdmin(CommandSender sender, String[] args) {
        // Check permission
        if (!sender.hasPermission("login.admin")) {
            sender.sendMessage(ChatColor.RED + plugin.getMessage("no-permission"));
            return true;
        }
        
        // Check arguments
        if (args.length < 1) {
            sender.sendMessage(ChatColor.RED + "Usage: /loginadmin <reset|unregister|forcelogin|reload> [player] [password]");
            return true;
        }
        
        String subCommand = args[0].toLowerCase();
        
        switch (subCommand) {
            case "reset":
                return handleAdminReset(sender, args);
            case "unregister":
                return handleAdminUnregister(sender, args);
            case "forcelogin":
                return handleAdminForceLogin(sender, args);
            case "reload":
                return handleAdminReload(sender);
            default:
                sender.sendMessage(ChatColor.RED + "Unknown subcommand. Use reset, unregister, forcelogin, or reload.");
                return true;
        }
    }
    
    private boolean handleAdminReset(CommandSender sender, String[] args) {
        if (args.length < 2) {
            sender.sendMessage(ChatColor.RED + "Usage: /loginadmin reset <player> [new password]");
            return true;
        }
        
        String playerName = args[1];
        Player target = Bukkit.getPlayer(playerName);
        
        if (target == null) {
            sender.sendMessage(ChatColor.RED + "Player not found: " + playerName);
            return true;
        }
        
        UUID targetUUID = target.getUniqueId();
        
        if (!plugin.isRegistered(targetUUID)) {
            sender.sendMessage(ChatColor.RED + "Player is not registered: " + playerName);
            return true;
        }
        
        // Generate random password if not provided
        String newPassword = args.length > 2 ? args[2] : generateRandomPassword();
        
        if (plugin.changePassword(targetUUID, newPassword)) {
            sender.sendMessage(ChatColor.GREEN + "Password reset for " + playerName + ". New password: " + newPassword);
            
            // Log player out if they're online
            if (plugin.isLoggedIn(targetUUID)) {
                plugin.setLoggedIn(target, false);
                target.sendMessage(ChatColor.RED + plugin.getMessage("admin-reset-password"));
            }
        } else {
            sender.sendMessage(ChatColor.RED + "Failed to reset password for " + playerName);
        }
        
        return true;
    }
    
    private boolean handleAdminUnregister(CommandSender sender, String[] args) {
        if (args.length < 2) {
            sender.sendMessage(ChatColor.RED + "Usage: /loginadmin unregister <player>");
            return true;
        }
        
        String playerName = args[1];
        Player target = Bukkit.getPlayer(playerName);
        
        if (target == null) {
            sender.sendMessage(ChatColor.RED + "Player not found: " + playerName);
            return true;
        }
        
        UUID targetUUID = target.getUniqueId();
        
        if (!plugin.isRegistered(targetUUID)) {
            sender.sendMessage(ChatColor.RED + "Player is not registered: " + playerName);
            return true;
        }
        
        if (plugin.unregisterUser(targetUUID)) {
            sender.sendMessage(ChatColor.GREEN + "Unregistered player: " + playerName);
            
            // Log player out if they're online
            if (plugin.isLoggedIn(targetUUID)) {
                plugin.setLoggedIn(target, false);
                target.sendMessage(ChatColor.RED + plugin.getMessage("admin-unregistered"));
            }
        } else {
            sender.sendMessage(ChatColor.RED + "Failed to unregister player: " + playerName);
        }
        
        return true;
    }
    
    private boolean handleAdminForceLogin(CommandSender sender, String[] args) {
        if (args.length < 2) {
            sender.sendMessage(ChatColor.RED + "Usage: /loginadmin forcelogin <player>");
            return true;
        }
        
        String playerName = args[1];
        Player target = Bukkit.getPlayer(playerName);
        
        if (target == null) {
            sender.sendMessage(ChatColor.RED + "Player not found: " + playerName);
            return true;
        }
        
        UUID targetUUID = target.getUniqueId();
        
        if (!plugin.isRegistered(targetUUID)) {
            sender.sendMessage(ChatColor.RED + "Player is not registered: " + playerName);
            return true;
        }
        
        if (plugin.isLoggedIn(targetUUID)) {
            sender.sendMessage(ChatColor.RED + "Player is already logged in: " + playerName);
            return true;
        }
        
        plugin.setLoggedIn(target, true);
        sender.sendMessage(ChatColor.GREEN + "Forced login for player: " + playerName);
        target.sendMessage(ChatColor.GREEN + plugin.getMessage("admin-force-login"));
        
        return true;
    }
    
    private boolean handleAdminReload(CommandSender sender) {
        plugin.reloadConfig();
        sender.sendMessage(ChatColor.GREEN + "SecureLogin configuration reloaded!");
        return true;
    }
    
    private String generateRandomPassword() {
        String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 8; i++) {
            int index = (int) (Math.random() * chars.length());
            sb.append(chars.charAt(index));
        }
        return sb.toString();
    }
}
