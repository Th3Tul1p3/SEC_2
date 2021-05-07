# reminder

\c pour afficher la base de donnée et l'utilisateur actuel

\dt+ pour afficher les tables

CREATE TABLE RIPE_OBJECT(
    ID INT PRIMARY  KEY         NOT NULL,
    INETNUM         CHAR(50)    NOT NULL,
    NETNAME         CHAR(50)    NOT NULL,
    COUNTRY         CHAR(5)     NOT NULL
);

\d RIPE_OBJECT pour avoir des infos sur la table 

