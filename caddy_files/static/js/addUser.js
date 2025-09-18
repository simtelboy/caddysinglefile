document.getElementById('addUserForm').addEventListener('submit',function(e){
    e.preventDefault();
    const formData = new FormData(this);
    const data = {};
    formData.forEach((value,key) => { data[key] = value });
    if (data.expiry_date) {
        const date = new Date(data.expiry_date);
        data.expiry_date = date.toISOString();
    }
        // 将 max_ips 转换为整数
    if (data.max_ips) {
        data.max_ips = parseInt(data.max_ips, 10);
        console.log("Converted max_ips to integer:", data.max_ips); // 检查整数转换是否正确
    }
    fetch('/admin/add_user',{
        method: 'POST',
        headers: {
            'Content-Type':'application/json'
        },
        body:JSON.stringify(data)
    }).then(response => {
        if (response.ok) {
            alert('添加用户成功');
           window.location.href = '/admin/userList'
        } else {
            //处理非200响应
            response.text().then(text => {
                alert('添加用户出错 :' + text);
            });
            alert('添加用户出错');
        }
    }).catch(error => {
        alert('添加用户出错');
    });
});

function loadUserList() {
    fetch('/admin/list_users').then(response => response.json()).then(users => {
        const userList = document.getElementById('userList');
        userList.innerHTML = '';
        users.forEach(user => {
            const div = document.createElement('div');
            div.textContent = `Username: ${user.username}, Email: ${user.email}, Tags: ${user.tags}, Max IPs: ${user.max_ips}, Expiry Date: ${user.expiry_date}`;
            userList.appendChild(div);
        });
    });
}

loadUserList();