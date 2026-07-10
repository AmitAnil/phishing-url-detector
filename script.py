rows, cols = map(int, input().split())
arr = [list(map(int, input().split())) for _ in range(rows)]

target = int(input("Enter the target value: "))

flag = 0

for i in range(rows):
    for j in range(cols):
        if arr[i][j] == target:
            flag = 1
            break
    if flag:
        break

if flag:
    print("Yes")
else:
    print("No")