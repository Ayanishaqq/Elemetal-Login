# SecureLogin

A secure login system with advanced inventory hiding for Minecraft servers.

## Features

- Secure password-based authentication
- Complete inventory and movement hiding until logged in
- Integration with ElementalCores for first-join experience
- Protection against brute force attacks
- Admin commands for account management
- Highly configurable

## Requirements

- Spigot/Paper 1.16.5 or higher
- ProtocolLib
- ElementalCores

## Installation

1. Download the latest release from the [Releases](https://github.com/yourusername/SecureLogin/releases) page
2. Place the JAR file in your server's `plugins` folder
3. Restart your server
4. Edit the configuration file as needed

## Commands

- `/register <password>` - Register a new account
- `/login <password>` - Log in to your account
- `/logout` - Log out of your account
- `/changepassword <old> <new>` - Change your password
- `/unregister <password>` - Delete your account
- `/loginadmin <subcommand>` - Admin commands (requires permission)

## Permissions

- `login.admin` - Access to admin commands

## Configuration

See `config.yml` for all configuration options.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
