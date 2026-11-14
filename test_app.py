import re
import io
import sqlite3
import pytest
from app import create_app

@pytest.fixture
def env(tmp_path):
    app=create_app(tmp_path)
    app.testing=True
    return app,tmp_path

def post(client,url,**data):
    client.get('/lab')
    with client.session_transaction() as s: csrf=s['csrf']
    return client.post(url,data={'csrf':csrf,**data})

def login(app,email,domain=None,password=None):
    c=app.test_client()
    return c,post(c,'/',email=email,domain=domain or email.split('@')[1],
                  password=password or ('Admin@123' if email.startswith('admin@') else 'Employee@123'))

def action(c,user,action):
    return post(c,f'/admin/employees/{user}/{action}')

def upload(c,content=b'company sample'):
    return post(c,'/employee/encrypt',file=(io.BytesIO(content),'file.txt'))

def lab_form(client,index=0):
    markup=client.get('/lab').get_data(as_text=True)
    tokens=re.findall(r'data-token="([^"]*)"',markup)
    with client.session_transaction() as state: csrf=state['csrf']
    return {'csrf':csrf,'target':tokens[index]}

def test_login_and_lab_roles(env):
    app,_=env
    assert login(app,'alice@north.example','south.example')[1].status_code==200
    assert b'incorrect' in login(app,'unknown@north.example')[1].data
    assert b'incorrect' in login(app,'alice@north.example',password='wrong')[1].data
    anonymous=app.test_client()
    assert anonymous.get('/lab').status_code==200
    assert anonymous.get('/admin').status_code==302
    assert anonymous.post('/').status_code==400
    employee,_=login(app,'alice@north.example')
    assert employee.get('/admin').status_code==403
    assert post(employee,'/admin/audit.csv').status_code==403

def test_employee_isolation_and_rotation(env):
    app,path=env
    admin,_=login(app,'admin@platform.example')
    people=[login(app,email)[0] for email in ('alice@north.example','ben@north.example','cara@south.example')]
    assert upload(people[0]).status_code==302
    for uid,user in enumerate(people,1):
        assert action(admin,uid,'assign').status_code==302
        assert upload(user,f'private-{uid}'.encode()).status_code==302
    assert action(admin,1,'assign').status_code==409
    with sqlite3.connect(path/'simulator.db') as db:
        ids=[r[0] for r in db.execute('select id from files order by user_id')]
        first=db.execute('select ciphertext,nonce,key_id from files where id=?',(ids[0],)).fetchone()
        assert db.execute('select count(distinct key_id) from files').fetchone()==(3,)
        material=[p.read_bytes() for p in (path/'keys').iterdir()]
        assert len(set(material))==3
    for c in people[1:]:
        assert post(c,f'/employee/files/{ids[0]}/download').status_code==404
    assert post(admin,f'/employee/files/{ids[0]}/download').status_code==403
    assert post(people[0],f'/employee/files/{ids[0]}/download').data==b'private-1'
    assert action(admin,2,'report').status_code==409
    lab=app.test_client()
    form=lab_form(lab)
    assert lab.post('/lab/simulate-theft',data={**form,'target':'ben@north.example'}).status_code==409
    assert lab.post('/lab/simulate-theft',data=form).status_code==200
    assert lab.post('/lab/simulate-theft',data=form).status_code==200
    with sqlite3.connect(path/'simulator.db') as db:
        assert db.execute('SELECT count(*) FROM incidents').fetchone()==(1,)
    assert 'open key incident' in admin.get('/incident-notice').json['message']
    assert 'reported compromised' in people[0].get('/incident-notice').json['message']
    assert all(not c.get('/incident-notice').json['message'] for c in people[1:])
    assert post(people[0],f'/employee/files/{ids[0]}/download').status_code==302
    assert post(people[1],f'/employee/files/{ids[1]}/download').data==b'private-2'
    assert action(admin,1,'revoke').status_code==302
    assert action(admin,1,'recover').status_code==302
    assert lab.post('/lab/simulate-theft',data=form).status_code==409
    assert 'Recovery complete' in people[0].get('/incident-notice').json['message']
    assert not admin.get('/incident-notice').json['message']
    assert post(people[0],f'/employee/files/{ids[0]}/download').data==b'private-1'
    with sqlite3.connect(path/'simulator.db') as db:
        assert all(a!=b for a,b in zip(first,db.execute('select ciphertext,nonce,key_id from files where id=?',(ids[0],)).fetchone()))
        assert db.execute("select count(*) from keys where status='active'").fetchone()==(3,)
    admin_html=admin.get('/admin').data
    assert all(key.hex().encode() not in admin_html+people[0].get('/employee').data for key in material)
    assert b'North Labs' in admin_html and b'South Research' in admin_html and b'FILE_RECOVERED' in admin_html
    assert b'RECOVERY_COMPLETE' in post(admin,'/admin/audit.csv').data

def test_tampered_file_recovery_is_atomic(env):
    app,path=env
    admin,_=login(app,'admin@platform.example')
    employee,_=login(app,'alice@north.example')
    action(admin,1,'assign')
    upload(employee)
    upload(employee,b'another file')
    with sqlite3.connect(path/'simulator.db') as db:
        db.execute("update files set ciphertext=zeroblob(length(ciphertext)) where id=(select max(id) from files)")
    lab=app.test_client()
    assert lab.post('/lab/simulate-theft',data=lab_form(lab)).status_code==200
    action(admin,1,'revoke')
    action(admin,1,'recover')
    assert b'No key or file changes' in admin.get('/admin').data
    with sqlite3.connect(path/'simulator.db') as db:
        assert db.execute('select version,status from keys').fetchall()==[(1,'revoked')]
        assert db.execute('select count(distinct key_id) from files').fetchone()==(1,)
    assert len(list((path/'keys').iterdir()))==1


@pytest.mark.parametrize('index,name',[(1,'Ben'),(2,'Cara')])
def test_other_demo_targets(env,index,name):
    app,path=env
    admin,_=login(app,'admin@platform.example')
    users=[login(app,email)[0] for email in ('alice@north.example','ben@north.example','cara@south.example')]
    for uid,user in enumerate(users,1):
        action(admin,uid,'assign')
        upload(user)
    lab=app.test_client()
    result=lab.post('/lab/simulate-theft',data=lab_form(lab,index))
    assert result.status_code==200 and f'Admin and {name}' in result.json['message']
    assert 'open key incident' in admin.get('/incident-notice').json['message']
    with sqlite3.connect(path/'simulator.db') as db:
        assert db.execute("SELECT user_id FROM keys WHERE status='compromised'").fetchall()==[(index+1,)]
        fid=db.execute('SELECT id FROM files WHERE user_id=?',(index+1,)).fetchone()[0]
    assert 'reported compromised' in users[index].get('/incident-notice').json['message']
    assert all(not u.get('/incident-notice').json['message'] for i,u in enumerate(users) if i!=index)
    action(admin,index+1,'revoke')
    action(admin,index+1,'recover')
    assert post(users[index],f'/employee/files/{fid}/download').data==b'company sample'
    assert 'Recovery complete' in users[index].get('/incident-notice').json['message']
