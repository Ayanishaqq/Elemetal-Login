package com.securelogin;

import com.comphenix.protocol.PacketType;
import com.comphenix.protocol.ProtocolLibrary;
import com.comphenix.protocol.ProtocolManager;
import com.comphenix.protocol.events.PacketAdapter;
import com.comphenix.protocol.events.PacketEvent;
import com.elementalcores.ElementalCores;
import org.bukkit.Bukkit;
import org.bukkit.ChatColor;
import org.bukkit.GameMode;
import org.bukkit.Location;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.configuration.file.FileConfiguration;
import org.bukkit.configuration.file.YamlConfiguration;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.entity.EntityDamageEvent;
import org.bukkit.event.entity.EntityTargetEvent;
import org.bukkit.event.entity.FoodLevelChangeEvent;
import org.bukkit.event.inventory.InventoryClickEvent;
import org.bukkit.event.inventory.InventoryOpenEvent;
import org.bukkit.event.player.*;
import org.bukkit.plugin.Plugin;
import org.bukkit.plugin.java.JavaPlugin;
import org.bukkit.potion.PotionEffect;
import org.bukkit.potion.PotionEffectType;
import org.bukkit.scheduler.BukkitRunnable;
import org.bukkit.scheduler.BukkitTask;

import java.io.File;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Level;

public class SecureLogin extends JavaPlugin implements Listener {
    
    // Core plugin variables
    private ProtocolManager protocolManager;
    private Set<UUID> loggedInPlayers = Collections.newSetFromMap(new ConcurrentHashMap<>());
    private Map<UUID, Location> frozenLocations = new HashMap<>();
    private Map<UUID, Integer> loginAttempts = new HashMap<>();
    private Map<UUID, BukkitTask> timeoutTasks = new HashMap<>();
    private ElementalCores elementalCores;
    
    // User data management
    private Map<UUID, UserData> users = new HashMap<>();
    private File userDataFile;
    private FileConfiguration userConfig;
    
    // Command manager
    private CommandManager commandManager;
    
    @Override
    public void onEnable() {
        // Create data folder if it doesn't exist
        if (!getDataFolder().exists()) {
            getDataFolder().mkdir();
        }
        
        // Save default config
        saveDefaultConfig();
        
        // Initialize user data
        initializeUserData();
        
        // Setup ProtocolLib
        setupProtocolLib();
        
        // Connect to ElementalCores
        connectToElementalCores();
        
        // Initialize command manager
        commandManager = new CommandManager(this);
        
        // Register all commands
        getCommand("register").setExecutor(commandManager);
        getCommand("login").setExecutor(commandManager);
        getCommand("logout").setExecutor(commandManager);
        getCommand("changepassword").setExecutor(commandManager);
        getCommand("loginadmin").setExecutor(commandManager);
        getCommand("unregister").setExecutor(commandManager);
        
        // Register event listeners
        getServer().getPluginManager().registerEvents(this, this);
        
        getLogger().info("SecureLogin has been enabled!");
    }
    
    @Override
    public void onDisable() {
        // Save all user data
        saveAllUsers();
        getLogger().info("SecureLogin has been disabled!");
    }
    
    // ========== USER DATA MANAGEMENT ==========
    
    private void initializeUserData() {
        userDataFile = new File(getDataFolder(), "userdata.yml");
        
        if (!userDataFile.exists()) {
            try {
                userDataFile.createNewFile();
            } catch (IOException e) {
                getLogger().severe("Could not create userdata.yml!");
                e.printStackTrace();
            }
        }
        
        loadAllUsers();
    }
    
    public void loadAllUsers() {
        userConfig = YamlConfiguration.loadConfiguration(userDataFile);
        
        for (String uuidStr : userConfig.getKeys(false)) {
            try {
                UUID uuid = UUID.fromString(uuidStr);
                String passwordHash = userConfig.getString(uuidStr + ".password");
                String salt = userConfig.getString(uuidStr + ".salt");
                
                UserData userData = new UserData(uuid, passwordHash, salt);
                users.put(uuid, userData);
            } catch (IllegalArgumentException e) {
                getLogger().warning("Invalid UUID in userdata.yml: " + uuidStr);
            }
        }
        
        getLogger().info("Loaded " + users.size() + " user accounts from database.");
    }
    
    public void saveAllUsers() {
        for (Map.Entry<UUID, UserData> entry : users.entrySet()) {
            UUID uuid = entry.getKey();
            UserData userData = entry.getValue();
            
            userConfig.set(uuid.toString() + ".password", userData.getPasswordHash());
            userConfig.set(uuid.toString() + ".salt", userData.getSalt());
        }
        
        try {
            userConfig.save(userDataFile);
            getLogger().info("Saved " + users.size() + " user accounts to database.");
        } catch (IOException e) {
            getLogger().severe("Could not save userdata.yml!");
            e.printStackTrace();
        }
    }
    
    public boolean isRegistered(UUID uuid) {
        return users.containsKey(uuid);
    }
    
    public boolean registerUser(UUID uuid, String password) {
        if (isRegistered(uuid)) {
            return false;
        }
        
        String salt = generateSalt();
        String passwordHash = hashPassword(password, salt);
        
        if (passwordHash == null) {
            return false;
        }
        
        UserData userData = new UserData(uuid, passwordHash, salt);
        users.put(uuid, userData);
        
        // Save to disk immediately
        userConfig.set(uuid.toString() + ".password", passwordHash);
        userConfig.set(uuid.toString() + ".salt", salt);
        try {
            userConfig.save(userDataFile);
        } catch (IOException e) {
            getLogger().severe("Could not save user data for " + uuid);
            e.printStackTrace();
            return false;
        }
        
        return true;
    }
    
    public boolean checkPassword(UUID uuid, String password) {
        if (!isRegistered(uuid)) {
            return false;
        }
        
        UserData userData = users.get(uuid);
        String salt = userData.getSalt();
        String hashedPassword = hashPassword(password, salt);
        
        return userData.getPasswordHash().equals(hashedPassword);
    }
    
    public boolean changePassword(UUID uuid, String newPassword) {
        if (!isRegistered(uuid)) {
            return false;
        }
        
        String salt = generateSalt();
        String passwordHash = hashPassword(newPassword, salt);
        
        if (passwordHash == null) {
            return false;
        }
        
        UserData userData = users.get(uuid);
        userData.setPasswordHash(passwordHash);
        userData.setSalt(salt);
        
        // Save to disk immediately
        userConfig.set(uuid.toString() + ".password", passwordHash);
        userConfig.set(uuid.toString() + ".salt", salt);
        try {
            userConfig.save(userDataFile);
        } catch (IOException e) {
            getLogger().severe("Could not save user data for " + uuid);
            e.printStackTrace();
            return false;
        }
        
        return true;
    }
    
    public boolean unregisterUser(UUID uuid) {
        if (!isRegistered(uuid)) {
            return false;
        }
        
        users.remove(uuid);
        
        // Remove from disk
        userConfig.set(uuid.toString(), null);
        try {
            userConfig.save(userDataFile);
        } catch (IOException e) {
            getLogger().severe("Could not unregister user " + uuid);
            e.printStackTrace();
            return false;
        }
        
        return true;
    }
    
    // ========== PROTOCOLLIB SETUP ==========
    
    private void setupProtocolLib() {
        try {
            protocolManager = ProtocolLibrary.getProtocolManager();
            
            // Block inventory-related packets for non-logged-in players
            protocolManager.addPacketListener(new PacketAdapter(this, 
                    PacketType.Play.Client.WINDOW_CLICK,
                    PacketType.Play.Client.PLAYER_BLOCK_PLACEMENT,
                    PacketType.Play.Client.USE_ITEM,
                    PacketType.Play.Client.PLAYER_DIGGING) {
                @Override
                public void onPacketReceiving(PacketEvent event) {
                    Player player = event.getPlayer();
                    if (!isLoggedIn(player.getUniqueId())) {
                        event.setCancelled(true);
                    }
                }
            });
            
            // Block movement packets for non-logged-in players
            protocolManager.addPacketListener(new PacketAdapter(this, 
                    PacketType.Play.Client.POSITION,
                    PacketType.Play.Client.POSITION_LOOK,
                    PacketType.Play.Client.LOOK,
                    PacketType.Play.Client.FLYING) {
                @Override
                public void onPacketReceiving(PacketEvent event) {
                    Player player = event.getPlayer();
                    if (!isLoggedIn(player.getUniqueId())) {
                        event.setCancelled(true);
                        
                        // Keep player in place
                        UUID uuid = player.getUniqueId();
                        if (frozenLocations.containsKey(uuid)) {
                            Location loc = frozenLocations.get(uuid);
                            // Only teleport if they've moved
                            if (!player.getLocation().equals(loc)) {
                                player.teleport(loc);
                            }
                        } else {
                            frozenLocations.put(uuid, player.getLocation());
                        }
                    }
                }
            });
            
        } catch (Exception e) {
            getLogger().log(Level.SEVERE, "Failed to initialize ProtocolLib support!", e);
            getServer().getPluginManager().disablePlugin(this);
        }
    }
    
    // ========== ELEMENTAL CORES INTEGRATION ==========
    
    private void connectToElementalCores() {
        Plugin plugin = getServer().getPluginManager().getPlugin("ElementalCores");
        if (plugin instanceof ElementalCores) {
            elementalCores = (ElementalCores) plugin;
            getLogger().info("Successfully connected to ElementalCores plugin!");
        } else {
            getLogger().warning("ElementalCores plugin not found or not compatible!");
            getLogger().warning("Core distribution after login will be disabled.");
            elementalCores = null;
        }
    }
    
    private void givePlayerCore(Player player) {
        if (elementalCores == null) return;
        
        // Check if this is a first join
        if (!player.hasPlayedBefore()) {
            try {
                // First, trigger the join animation for new players
                java.lang.reflect.Method playFirstJoinAnimation = elementalCores.getClass().getDeclaredMethod("playFirstJoinAnimation", Player.class);
                playFirstJoinAnimation.setAccessible(true);
                playFirstJoinAnimation.invoke(elementalCores, player);
                
                getLogger().info("Triggered core animation for new player: " + player.getName());
            } catch (Exception e) {
                getLogger().log(Level.WARNING, "Failed to trigger core animation for player: " + player.getName(), e);
                
                // Fallback: directly give a random core
                try {
                    java.lang.reflect.Method giveRandomCore = elementalCores.getClass().getDeclaredMethod("giveRandomCore", Player.class);
                    giveRandomCore.setAccessible(true);
                    giveRandomCore.invoke(elementalCores, player);
                    
                    getLogger().info("Gave random core to player: " + player.getName());
                } catch (Exception ex) {
                    getLogger().log(Level.SEVERE, "Failed to give core to player: " + player.getName(), ex);
                }
            }
        }
    }
    
    // ========== LOGIN SYSTEM METHODS ==========
    
    public boolean isLoggedIn(UUID uuid) {
        return loggedInPlayers.contains(uuid);
    }
    
    public void setLoggedIn(Player player, boolean loggedIn) {
        UUID uuid = player.getUniqueId();
        
        if (loggedIn) {
            loggedInPlayers.add(uuid);
            loginAttempts.remove(uuid);
            
            // Remove frozen location
            frozenLocations.remove(uuid);
            
            // Cancel any timeout task
            if (timeoutTasks.containsKey(uuid)) {
                timeoutTasks.get(uuid).cancel();
                timeoutTasks.remove(uuid);
            }
            
            // Start session timeout task
            int timeoutMinutes = getConfig().getInt("session.timeout-minutes", 60);
            if (timeoutMinutes > 0) {
                BukkitTask task = new BukkitRunnable() {
                    @Override
                    public void run() {
                        if (player.isOnline()) {
                            setLoggedIn(player, false);
                            player.sendMessage(ChatColor.RED + getMessage("session-timeout"));
                            applyLoginRestrictions(player);
                        }
                    }
                }.runTaskLater(this, timeoutMinutes * 60 * 20L);
                
                timeoutTasks.put(uuid, task);
            }
            
            // Remove login restrictions
            removeLoginRestrictions(player);
            
            // Give player their elemental core if ElementalCores is enabled
            if (elementalCores != null) {
                // Schedule this to run after the player is fully logged in
                new BukkitRunnable() {
                    @Override
                    public void run() {
                        givePlayerCore(player);
                    }
                }.runTaskLater(this, 20L); // 1 second delay
            }
        } else {
            loggedInPlayers.remove(uuid);
            
            // Apply login restrictions
            if (player.isOnline()) {
                applyLoginRestrictions(player);
            }
            
            // Cancel any timeout task
            if (timeoutTasks.containsKey(uuid)) {
                timeoutTasks.get(uuid).cancel();
                timeoutTasks.remove(uuid);
            }
        }
    }
    
    public void applyLoginRestrictions(Player player) {
        // Store their location to prevent movement
        frozenLocations.put(player.getUniqueId(), player.getLocation());
        
        // Hide player inventory (will be restored after login)
        player.setGameMode(GameMode.ADVENTURE);
        
        // Apply blindness and slowness
        player.addPotionEffect(new PotionEffect(PotionEffectType.BLINDNESS, Integer.MAX_VALUE, 1, false, false));
        player.addPotionEffect(new PotionEffect(PotionEffectType.SLOW, Integer.MAX_VALUE, 10, false, false));
        
        // Send login message
        if (isRegistered(player.getUniqueId())) {
