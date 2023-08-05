# address-book

Passwords are generated using SHA256
https://emn178.github.io/online-tools/sha256.html

Execute following command to run the server on your local.

`npm run start`

Here are the curl requests

```
curl --location --request POST 'http://localhost:5000/auth/v1/login' \
--header 'Content-Type: application/json' \
--data-raw '{
    "phoneNumber": "9200200200",
    "password": "Aman1234"
}'
Response
{
    "loginToken": "8e99-e344c4d8-1b3d-2b0bddc74c84-8c1e307f97d6-4388-14066795518165964-b484-408c-5ed566f9-133e-8803527227295433",
    "phoneNumber": "9200200200"
}
```

Send the loginToken and phoneNumber value in the rest the APIs. Sample
```
fetch("http://localhost:3000/users", {
  "headers": {
    "x-auth-phone": "9200200200",
    "x-auth-token": "8e99-e344c4d8-1b3d-2b0bddc74c84-8c1e307f97d6-4388-14066795518165964-b484-408c-5ed566f9-133e-8803527227295433"
  },
  "method": "GET",
});


curl 'http://localhost:3000/users' \
  -H 'x-auth-phone: 9000000000' \
  -H 'x-auth-token: 8e99-e344c4d8-1b3d-2b0bddc74c84-8c1e307f97d6-4388-14066795518165964-b484-408c-5ed566f9-133e-8803527227295433' \
  --compressed
```

If you will not pass these headers then following error will be thrown by backend
```
{"message":"Unauthorized request. Please do login first."}
```



Now in the following examples, I have not mentioned about these 2 headers, but u need to pass them.. Soon I will update them.


```
Create user.

curl --location 'localhost:3000/users' \
--header 'Content-Type: application/json' \
--data-raw '{
    "name": "Manoj V Patel",
    "email": "mv.patel@gmails.com",
    "city": "Surat",
    "phoneNumber": ["890-009-0909", "909-101-4000"]
}'

{
    "name": "Manoj V Patel",
    "email": "mv.patel@gmails.com",
    "city": "Surat",
    "phoneNumber": [
        "890-009-0909",
        "909-101-4000"
    ],
    "id": "user_3182d853-c002-461d-af20-94978f6a2a56"
}

____________________________________________________________

Get all users.
curl --location 'localhost:3000/users'

[
 {
     "name": "Manoj V Patel",
     "email": "mv.patel@gmails.com",
     "city": "Surat",
     "phoneNumber": [
         "890-009-0909",
         "909-101-4000"
     ],
     "id": "user_6453a5a8-6ac0-4b66-9e19-ee1b02ba0d81"
 },
 {
     "name": "Anokhi S Shah",
     "email": "anokhi.spl@shah-pvt-ltd.com",
     "city": "Hyderabad",
     "phoneNumber": [
         "909-009-1111"
     ],
     "id": "user_6f2e328d-b5c4-4978-9d0b-031131ce1f35"
 }
]

_______________________________________________________________

Update user. Send the fields that are required to be updated.

curl --location --request PUT 'localhost:3000/users/user_6453a5a8-6ac0-4b66-9e19-ee1b02ba0d81' \
--header 'Content-Type: application/json' \
--data '{
    "name": "Pritesh Paul",
    "city": "Ahmedabad"
}'

{
 "name": "Pritesh Paul",
 "email": "mv.patel@gmails.com",
 "city": "Ahmedabad",
 "phoneNumber": [
     "890-009-0909",
     "909-101-4000"
 ],
 "id": "user_6453a5a8-6ac0-4b66-9e19-ee1b02ba0d81"
}


_______________________________________________________________

Delete user. 

curl --location --request DELETE 'localhost:3000/users/user_6453a5a8-6ac0-4b66-9e19-ee1b02ba0d81'

{
 "name": "Pritesh Paul",
 "email": "mv.patel@gmails.com",
 "city": "Ahmedabad",
 "phoneNumber": [
     "890-009-0909",
     "909-101-4000"
 ],
 "id": "user_6453a5a8-6ac0-4b66-9e19-ee1b02ba0d81"
}

```
