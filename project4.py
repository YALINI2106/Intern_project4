import string
import secrets
import sys

try:
    import pyperclip

    PYPERCLIP_AVAILABLE = True
except ImportError:
    PYPERCLIP_AVAILABLE = False


def get_user_preferences():
    print("=== Secure Password Generator ===\n")

    # Get password length
    while True:
        try:
            length = int(input("Enter desired password length (e.g., 12): "))
            if length < 4:
                print("Password length should be at least 4 characters for better security.")
                continue
            break
        except ValueError:
            print("Please enter a valid integer for the password length.")

    # Character types
    include_lowercase = get_yes_no("Include lowercase letters? (y/n): ")
    include_uppercase = get_yes_no("Include uppercase letters? (y/n): ")
    include_numbers = get_yes_no("Include numbers? (y/n): ")
    include_symbols = get_yes_no("Include symbols? (y/n): ")

    if not any([include_lowercase, include_uppercase, include_numbers, include_symbols]):
        print("At least one character type must be selected. Please try again.\n")
        return get_user_preferences()

    return {
        'length': length,
        'lowercase': include_lowercase,
        'uppercase': include_uppercase,
        'numbers': include_numbers,
        'symbols': include_symbols
    }


def get_yes_no(prompt):
    while True:
        choice = input(prompt).strip().lower()
        if choice in ['y', 'yes']:
            return True
        elif choice in ['n', 'no']:
            return False
        else:
            print("Please enter 'y' for yes or 'n' for no.")


def generate_password(criteria):
    character_pool = ''
    if criteria['lowercase']:
        character_pool += string.ascii_lowercase
    if criteria['uppercase']:
        character_pool += string.ascii_uppercase
    if criteria['numbers']:
        character_pool += string.digits
    if criteria['symbols']:
        character_pool += string.punctuation

    if not character_pool:
        raise ValueError("No characters available to generate password.")

    # Ensure the password has at least one character from each selected type
    password = []
    if criteria['lowercase']:
        password.append(secrets.choice(string.ascii_lowercase))
    if criteria['uppercase']:
        password.append(secrets.choice(string.ascii_uppercase))
    if criteria['numbers']:
        password.append(secrets.choice(string.digits))
    if criteria['symbols']:
        password.append(secrets.choice(string.punctuation))

    # Fill the remaining length
    while len(password) < criteria['length']:
        password.append(secrets.choice(character_pool))

    # Shuffle the password list to prevent predictable sequences
    secrets.SystemRandom().shuffle(password)

    return ''.join(password)


def copy_to_clipboard(password):
    if not PYPERCLIP_AVAILABLE:
        print("\nNote: 'pyperclip' library not installed. Install it to enable clipboard functionality.")
        print("You can install it using: pip install pyperclip")
        return
    try:
        pyperclip.copy(password)
        print("Password copied to clipboard.")
    except pyperclip.PyperclipException:
        print("Failed to copy password to clipboard.")


def main():
    while True:
        criteria = get_user_preferences()
        password = generate_password(criteria)

        print("\n=== Generated Password ===")
        print(password)

        # Option to copy to clipboard
        if PYPERCLIP_AVAILABLE:
            copy = get_yes_no("Copy password to clipboard? (y/n): ")
            if copy:
                copy_to_clipboard(password)
        else:
            print("\n'pyperclip' library not available. Install it to enable clipboard functionality.")

        # Option to generate another password
        again = get_yes_no("\nDo you want to generate another password? (y/n): ")
        if not again:
            print("Thank you for using the Secure Password Generator! Goodbye!")
            sys.exit()


if __name__ == "__main__":
    main()
