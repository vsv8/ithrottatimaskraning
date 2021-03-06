DROP TABLE IF EXISTS signatures;

CREATE TABLE signatures(
  id serial primary key,
  name varchar(128) not null,
  phone varchar(400) not null unique,
  comment varchar(400),
  signed timestamp with time zone not null default current_timestamp
);
