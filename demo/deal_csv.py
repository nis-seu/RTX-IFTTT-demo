
# read the file
def read(csv_file):
    data = []
    with open(csv_file, "r", encoding='utf-8') as file:
        lines = file.readlines()
        num =  lines[0].count(',') + 1
        for line in lines:
            line =  line.replace('\n', '').split(',', num)
            data.append(line)
    return data

# read the file
def read_csv(csv_file):
    data = []
    with open(csv_file, "r", encoding='utf-8') as file:
        lines = file.readlines()
        num =  lines[0].count(',') + 1
        for line in lines:
            line =  line.replace('\n', '').split(',', num-1)
            data.append(line)
    return data



# save data to file
def to_csv(file_path, data):
    with open(file_path, "w", encoding='utf-8') as file :
        file.write("")
    with open(file_path, "a", encoding='utf-8') as file:
        for item in data:
            file.write(str(item[0]))
            for i in range(1, len(item)):
                file.write(','+ str(item[i]))
            file.write('\n')

