package pkg

import "github.com/google/uuid"


type User struct {
	id 			uuid.UUID
	FirstName 	string
	LastName 	string
	Username	string
	Email       string
	Password	string
}

type Login struct{
	Email 		string
	Password	string 
}