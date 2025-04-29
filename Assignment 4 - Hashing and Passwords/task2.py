import bcrypt
import nltk
import time
import multiprocessing
from datetime import timedelta
import os

# download NLTK words corpus if not already downloaded
nltk.download('words', quiet=True)
from nltk.corpus import words

def load_shadow_file(filepath):
    """load the shadow file and parse user entries."""
    try:
        with open(filepath, 'r') as file:
            content = file.read()
        
        lines = content.splitlines() # split by newlines for each user entry
        
        users = []
        for line in lines:
            line = line.strip()
            if not line:  # skip empty lines
                continue
            
            # parse username and hash
            if ':' in line:
                parts = line.split(':', 1)
                username, hash_data = parts
                hash_data = hash_data.strip()   # remove whitespace
                users.append((username, hash_data))
        
        if not users:
            print("Warning: No valid user entries found in the shadow file!")
        
        return users
    except Exception as e:
        print(f"Error loading shadow file: {e}")
        return []

def filter_words(word_list):
    """Filter words to only include those between 6 and 10 letters."""
    return [word.lower() for word in word_list if 6 <= len(word) <= 10]

def crack_password(user_data, word_chunk, result_queue):
    """Try to crack a user's password using a chunk of the dictionary."""
    username, hash_data = user_data
    
    hash_data_bytes = hash_data.encode('utf-8') # for bcrypt, we need the hash as bytes
    start_time = time.time()
    
    for word in word_chunk:
        # test each word
        if bcrypt.checkpw(word.encode('utf-8'), hash_data_bytes):
            end_time = time.time()
            elapsed = end_time - start_time
            result_queue.put((username, word, elapsed))
            return
    
    result_queue.put((username, None, time.time() - start_time)) # if no match was found

def divide_chunks(word_list, num_chunks):
    """divide a list into approximately equal chunks."""
    avg_chunk_size = len(word_list) // num_chunks
    remainder = len(word_list) % num_chunks
    
    chunks = []
    start = 0
    
    for i in range(num_chunks):
        # add one extra item to the first 'remainder' chunks to distribute remainder
        chunk_size = avg_chunk_size + (1 if i < remainder else 0)
        end = start + chunk_size
        chunks.append(word_list[start:end])
        start = end
    
    return chunks

def extract_workfactor(hash_data):
    """Extract the workfactor from a bcrypt hash."""
    try:
        # format: $2b$XX$...
        parts = hash_data.split('$')
        if len(parts) >= 3:
            return int(parts[2])
        return 10  # default if we can't extract
    except (ValueError, IndexError):
        return 10  # default if we can't extract

def crack_all_passwords(shadow_file, num_processes=None):
    """Crack all passwords in the shadow file using multiprocessing."""
    if num_processes is None:
        # use number of CPU cores - 1 (to leave one core for system)
        num_processes = max(1, multiprocessing.cpu_count() - 1)
    
    print(f"Using {num_processes} processes for cracking")
    
    # load user data from shadow file
    print(f"Loading shadow file: {shadow_file}")
    users = load_shadow_file(shadow_file)
    print(f"Found {len(users)} users")
    
    # get word corpus and filter to 6-10 letter words
    print("Loading NLTK word corpus...")
    word_list = words.words()
    filtered_words = filter_words(word_list)
    print(f"Dictionary contains {len(filtered_words)} words (6-10 letters)")
    
    # statistics for reporting
    results = {}
    
    # process each user
    for user_idx, user_data in enumerate(users):
        username, hash_data = user_data
        print(f"\nWorking on user {user_idx+1}/{len(users)}: {username}")
        
        # extract workfactor to estimate time
        workfactor = extract_workfactor(hash_data)
        estimated_time_per_hash_ms = 30 * (2 ** (workfactor - 8))  # Based on given benchmark
        estimated_total_time_single_core = estimated_time_per_hash_ms * len(filtered_words) / 1000
        estimated_time_with_parallelism = estimated_total_time_single_core / num_processes
        
        print(f"Workfactor: {workfactor}, Est. time per hash: {estimated_time_per_hash_ms:.1f}ms")
        print(f"Est. worst-case time (all words): {timedelta(seconds=estimated_time_with_parallelism)}")
        
        user_start_time = time.time() # start timer for this user
        
        # divide dictionary into chunks for parallel processing
        word_chunks = divide_chunks(filtered_words, num_processes)
        
        # create a queue for results
        result_queue = multiprocessing.Queue()
        
        # start processes
        processes = []
        for chunk in word_chunks:
            p = multiprocessing.Process(
                target=crack_password, 
                args=(user_data, chunk, result_queue)
            )
            processes.append(p)
            p.start()
        
        # wait for first result or all processes to finish
        found_password = False
        while not found_password and any(p.is_alive() for p in processes):
            if not result_queue.empty():
                result_username, password, process_time = result_queue.get()
                if password is not None:
                    found_password = True
                    user_end_time = time.time()
                    total_time = user_end_time - user_start_time
                    print(f"PASSWORD FOUND! User: {result_username}, Password: {password}")
                    print(f"Time taken: {timedelta(seconds=total_time)}")
                    results[result_username] = (password, total_time)
            time.sleep(0.1)  # small sleep to prevent CPU hogging
        
        # terminate all processes if password found
        for p in processes:
            if p.is_alive():
                p.terminate()
        
        # if we didn't find the password already, check the queue for any final results
        if not found_password:
            while not result_queue.empty():
                result_username, password, process_time = result_queue.get()
                if password is not None:
                    user_end_time = time.time()
                    total_time = user_end_time - user_start_time
                    print(f"PASSWORD FOUND! User: {result_username}, Password: {password}")
                    print(f"Time taken: {timedelta(seconds=total_time)}")
                    results[result_username] = (password, total_time)
                    found_password = True
                    break
        
        # if still no password found
        if not found_password:
            print(f"No password found for user {username} after checking all words")
            results[username] = (None, time.time() - user_start_time)
    
    # print final summary
    print("\n===== SUMMARY =====")
    for username, (password, time_taken) in results.items():
        if password:
            print(f"User: {username}, Password: {password}, Time: {timedelta(seconds=time_taken)}")
        else:
            print(f"User: {username}, Password: NOT FOUND, Time: {timedelta(seconds=time_taken)}")
    
    return results

if __name__ == "__main__":
    # use shadowfile.txt in the current directory, getting the script's directory
    import os
    script_dir = os.path.dirname(os.path.abspath(__file__))
    shadow_file = os.path.join(script_dir, "shadowfile.txt")
    
    # check if the file exists at the expected location
    if not os.path.exists(shadow_file):
        # try current working directory
        shadow_file = "shadowfile.txt"
    
    print(f"Using shadow file: {shadow_file}")
    
    # get number of processes to use
    try:
        num_cores = multiprocessing.cpu_count()
        suggested_processes = max(1, num_cores - 1)  # Leave one core for system
        processes_input = input(f"Number of processes to use (default: {suggested_processes}): ")
        num_processes = int(processes_input) if processes_input.strip() else suggested_processes
    except ValueError:
        print(f"Invalid input, using default: {suggested_processes}")
        num_processes = suggested_processes
    
    # run the password cracker
    crack_all_passwords(shadow_file, num_processes)