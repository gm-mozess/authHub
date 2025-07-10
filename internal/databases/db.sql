CREATE TABLE Users {
    Id TEXT NOT NULL PRIMARY KEY,
    Firstname TEXT NOT NULL,
    Lastname TEXT NOT NULL,
    Username TEXT NOT NULL,
    Email TEXT NOT NULL,
    Password TEXT NOT NULL,
}

CREATE TABLE Sessions{
    Id TEXT NOT NULL PRIMARY KEY,
    Expires BOOLEAN,
}