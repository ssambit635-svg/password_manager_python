"""
constants.py

Every magic number, file name and word list lives here. When I was learning
Python I used to sprinkle strings like "passwords.json" all over the code and
then forget to change one of them. Now they are all in one place, so if the
name of a file ever has to change, it only changes once.
"""

# ---------------------------------------------------------------------------
# Names and versions
# ---------------------------------------------------------------------------

APP_NAME = "SecureVault"
APP_VERSION = "2.0.0"
SCHEMA_VERSION = 2

# ---------------------------------------------------------------------------
# Files that the program creates inside the data directory
# ---------------------------------------------------------------------------

META_FILE = "meta.json"
VAULT_FILE = "vault.enc"
DECOY_VAULT_FILE = "decoy_vault.enc"
BACKUP_DIR = "backups"
EMERGENCY_KIT_FILE = "emergency_kit.txt"

# The environment variable people can set if they want the vault somewhere
# else. It is handy for tests and for keeping the vault on a USB stick.
DATA_DIR_ENV_VAR = "SECUREVAULT_HOME"

# ---------------------------------------------------------------------------
# Crypto settings
# ---------------------------------------------------------------------------

# How many times PBKDF2 mixes the master password. Bigger is slower for you
# and slower for somebody guessing. Around 300k takes a fraction of a second
# on a normal laptop, which feels fine when you unlock a vault twice a day.
DEFAULT_ITERATIONS = 320000

# A backup file gets its own passphrase, so it gets its own (slightly lower)
# iteration count. The backup passphrase is usually longer and stronger than
# a master password, and backups are made more often, so this keeps the
# waiting time sensible.
BACKUP_ITERATIONS = 260000

# Salt size in bytes. 16 bytes is the usual recommendation and is plenty.
SALT_BYTES = 16

# The master password minimum. Short passwords are sadly very common and
# very easy to guess, so we refuse anything under eight characters.
MIN_MASTER_LENGTH = 8
MIN_NEW_PASSWORD_LENGTH = 6

# ---------------------------------------------------------------------------
# Login protection
# ---------------------------------------------------------------------------

MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_BASE_SECONDS = 30
LOCKOUT_MAX_SECONDS = 3600

# How long a vault stays open when you stop touching the keyboard.
DEFAULT_AUTO_LOCK_SECONDS = 300
MIN_AUTO_LOCK_SECONDS = 30
MAX_AUTO_LOCK_SECONDS = 3600

# How long a copied password stays on the clipboard.
DEFAULT_CLIPBOARD_SECONDS = 20

# Passwords older than this get a gentle warning in the health report.
PASSWORD_AGE_WARNING_DAYS = 180

# The audit log is not a diary. Keep the last N actions only.
MAX_AUDIT_LOG_ENTRIES = 200

# ---------------------------------------------------------------------------
# Character sets used by the password generator
# ---------------------------------------------------------------------------

LOWERCASE_LETTERS = "abcdefghijklmnopqrstuvwxyz"
UPPERCASE_LETTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
DIGITS = "0123456789"
SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?/"

# These characters look almost the same in many fonts. If you have to read a
# password off a screen and type it into a phone, they are a nightmare, so
# the generator can leave them out.
AMBIGUOUS_CHARACTERS = "O0oIl1|5S2Z8B"

# A few ready made mixes for the "preset" option in the generator menu.
PRESET_BALANCED = "balanced"
PRESET_PARANOID = "paranoid"
PRESET_MEMORABLE = "memorable"
PRESET_PIN = "pin"
PRESET_PASSPHRASE = "passphrase"

GENERATOR_PRESETS = [
    PRESET_BALANCED,
    PRESET_PARANOID,
    PRESET_MEMORABLE,
    PRESET_PIN,
    PRESET_PASSPHRASE,
]

# ---------------------------------------------------------------------------
# Share codes
# ---------------------------------------------------------------------------

# A share blob starts with this text so that we can tell, before trying to
# decrypt anything, that the person pasted the right kind of thing.
SHARE_CODE_PREFIX = "SVSHARE1."
SHARE_CODE_ITERATIONS = 200000

# ---------------------------------------------------------------------------
# TOTP (the six digit codes from authenticator apps)
# ---------------------------------------------------------------------------

TOTP_PERIOD = 30
TOTP_DIGITS = 6
TOTP_SECRET_BYTES = 20
TOTP_ALGORITHM = "sha1"

# ---------------------------------------------------------------------------
# Word list for passphrases
# ---------------------------------------------------------------------------
# These are short, easy to spell, easy to say words. A four word passphrase
# picked from this list still has a lot of combinations, and it is much
# easier to remember than "j8#Lq2!v". Real diceware lists have 7776 words;
# this one is shorter because it is meant for a small project, and because
# every extra word here is another line somebody has to read.
WORDLIST = [
    "amber", "anchor", "apple", "arrow", "atlas", "autumn", "bacon", "badge",
    "bagel", "baker", "bamboo", "banana", "banjo", "barrel", "basket", "beach",
    "beacon", "beagle", "bean", "bear", "beaver", "bench", "berry", "bicycle",
    "birch", "biscuit", "bison", "blanket", "blossom", "bluebird", "board", "boat",
    "bobcat", "bonfire", "book", "boot", "border", "bottle", "boulder", "breeze",
    "bridge", "bronze", "brook", "bubble", "bucket", "buffalo", "bugle", "bunny",
    "burrow", "butter", "button", "cabin", "cactus", "camel", "candle", "candy",
    "canoe", "canyon", "caramel", "cargo", "carpet", "carrot", "castle", "cat",
    "cedar", "cello", "chalk", "cheese", "cherry", "chess", "chest", "chicken",
    "chimney", "chinch", "cider", "cinema", "circle", "citrus", "clay", "cliff",
    "clock", "cloud", "clover", "coast", "cobalt", "coconut", "coffee", "comet",
    "compass", "copper", "coral", "cotton", "cougar", "coyote", "crane", "crater",
    "crayon", "creek", "cricket", "crown", "crystal", "cube", "cucumber", "cupcake",
    "curtain", "cycle", "daisy", "dance", "dandelion", "dawn", "deer", "delta",
    "denim", "desert", "diamond", "dice", "dolphin", "donkey", "doodle", "dragon",
    "drum", "duck", "dune", "eagle", "earth", "echo", "eel", "elbow",
    "elder", "ember", "emerald", "engine", "ensign", "ermine", "falcon", "fancy",
    "feather", "fence", "fern", "ferry", "fiddle", "field", "fig", "finch",
    "fire", "fish", "flag", "flame", "flask", "fleet", "flint", "flour",
    "flower", "flute", "fog", "forest", "fossil", "fountain", "fox", "frame",
    "frost", "fruit", "galaxy", "garden", "garlic", "gate", "gecko", "geese",
    "gem", "ginger", "giraffe", "glacier", "glass", "globe", "glove", "gold",
    "goose", "gopher", "granite", "grape", "grass", "gravel", "green", "grove",
    "guitar", "gull", "hammer", "harbor", "harp", "harvest", "hawk", "hazel",
    "heart", "hedge", "helmet", "heron", "hickory", "hill", "honey", "hoop",
    "horizon", "horse", "house", "hunter", "ice", "igloo", "indigo", "ink",
    "island", "ivory", "jacket", "jaguar", "jasmine", "jelly", "jersey", "jewel",
    "journey", "jungle", "junior", "kayak", "keeper", "kettle", "key", "kite",
    "kitten", "koala", "ladder", "lagoon", "lake", "lamp", "lantern", "lark",
    "laser", "latch", "leaf", "lemon", "lentil", "leopard", "letter", "lily",
    "lime", "linen", "lion", "lizard", "lobster", "locket", "lotus", "lucky",
    "lunar", "lynx", "magnet", "mango", "maple", "marble", "march", "marina",
    "market", "marsh", "mask", "meadow", "melon", "mentor", "mercury", "mermaid",
    "metal", "meteor", "mint", "mirror", "mist", "mitten", "mocha", "monkey",
    "moon", "moose", "morning", "mosaic", "moss", "moth", "mountain", "mouse",
    "muffin", "mulberry", "museum", "music", "mustard", "napkin", "nectar", "needle",
    "nest", "night", "noble", "noodle", "north", "nova", "nutmeg", "oak",
    "oasis", "ocean", "olive", "onion", "onyx", "opal", "orange", "orbit",
    "orchid", "osprey", "otter", "oven", "owl", "oyster", "paddle", "palace",
    "palette", "palm", "panda", "pantry", "paper", "parrot", "pastel", "path",
    "peach", "peacock", "pearl", "pebble", "pelican", "penguin", "pepper", "petal",
    "pewter", "piano", "pickle", "pigeon", "pillow", "pilot", "pine", "pistol",
    "planet", "plum", "pluto", "pocket", "polar", "pollen", "ponder", "poppy",
    "porch", "portal", "potato", "prairie", "pretzel", "prism", "puddle", "puffin",
    "pumpkin", "puzzle", "pyramid", "quartz", "quill", "quilt", "rabbit", "raccoon",
    "radar", "radish", "raft", "rain", "rainbow", "raisin", "raven", "reef",
    "ribbon", "rice", "ridge", "river", "robin", "rocket", "rodeo", "rooster",
    "rose", "ruby", "rudder", "rust", "saddle", "saffron", "sage", "salmon",
    "sand", "sapphire", "saturn", "scooter", "sea", "seed", "shadow", "shell",
    "shelter", "shore", "shrimp", "silver", "sketch", "sky", "sled", "sloth",
    "smile", "snail", "snow", "sock", "solar", "song", "sparrow", "spice",
    "spider", "spiral", "sponge", "spoon", "spring", "spruce", "square", "squash",
    "squirrel", "stable", "star", "statue", "steam", "steel", "stone", "storm",
    "stream", "straw", "summer", "sun", "swan", "sweet", "sword", "table",
    "tangerine", "tapestry", "tea", "temple", "tent", "teal", "thistle", "thunder",
    "tiger", "timber", "toast", "tomato", "topaz", "torch", "tortoise", "tower",
    "trail", "treat", "tree", "tulip", "tundra", "tunnel", "turkey", "turtle",
    "twig", "umbrella", "unicorn", "valley", "vanilla", "vase", "velvet", "vessel",
    "violet", "violin", "vision", "volcano", "voyage", "walnut", "walrus", "wand",
    "water", "weasel", "whale", "wheat", "wheel", "willow", "wind", "window",
    "winter", "wolf", "wonder", "wood", "wool", "yacht", "yam", "yard",
    "yarrow", "yellow", "yogurt", "zebra", "zenith", "zephyr", "zinc", "zinnia",
]

# ---------------------------------------------------------------------------
# A small list of passwords that show up again and again in leaked databases
# ---------------------------------------------------------------------------
# This is nowhere near a real breach database, of course. It is just enough
# to catch the classics. The health report also checks whether a password is
# built out of a site name plus a year, because that is what people do.
COMMON_PASSWORDS = [
    "123456", "123456789", "12345678", "1234567", "12345", "1234567890",
    "password", "password1", "password123", "password1234", "passw0rd",
    "qwerty", "qwerty123", "qwertyuiop", "abc123", "abcd1234", "letmein",
    "welcome", "welcome1", "welcome123", "admin", "admin123", "root",
    "login", "master", "monkey", "dragon", "sunshine", "princess",
    "football", "baseball", "basketball", "soccer", "hockey", "batman",
    "superman", "spiderman", "pokemon", "starwars", "whatever", "trustno1",
    "iloveyou", "lovely", "lovers", "hello", "hello123", "freedom",
    "shadow", "michael", "jennifer", "jordan", "charlie", "daniel",
    "andrew", "joshua", "matthew", "nicole", "hunter", "summer",
    "winter", "spring", "autumn", "computer", "internet", "samsung",
    "google", "facebook", "instagram", "snapchat", "twitter", "linkedin",
    "youtube", "netflix", "spotify", "amazon", "apple", "microsoft",
    "secret", "secret123", "mypassword", "mypass", "changeme", "default",
    "test", "test123", "testing", "guest", "user", "user123",
    "access", "pass", "pass123", "passion", "qazwsx", "zaq12wsx",
    "1q2w3e4r", "1qaz2wsx", "asdfgh", "asdfghjkl", "zxcvbn", "zxcvbnm",
    "aaaaaa", "111111", "000000", "121212", "666666", "987654321",
    "741852963", "159753", "112233", "123123", "654321", "555555",
    "qwerty12", "qwerty1234", "letmein123", "welcome2024", "password2024",
    "summer2024", "iloveyou1", "1234abcd", "abcd1234", "q1w2e3r4",
]

# Used by the deterministic password studio. Changing this would change
# every password that studio produces, which would be very annoying, so it
# gets its own constant and a comment telling future me not to touch it.
DETERMINISTIC_PEPPER = "securevault-deterministic-v1"

# ---------------------------------------------------------------------------
# Little bits of presentation
# ---------------------------------------------------------------------------

MENU_WIDTH = 70
TABLE_WIDTH = 78
