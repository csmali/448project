# 448project

Uygulamayi kullanmak isteyen kullanici login ekranindan asagidaki user:password ciftlerinden birini kullanir

cs470:cs470
cs471:cs471
cs472:cs472
cs473:cs473
cs474:cs474

Room olarak "A" ya da "B" yazarak connect'e basar

Client   Server arasinda asagidaki mesajlasma yasanir

client server

--Hello->

<--randomNumber up to 65536--

 -{Hashed(16timesHashed(userPassword)xor randomNumber)concat roomName} encrypted with server pub. key-->

bu esnada Hashed(16timesHashed(userPassword)xor randomNumber) = tempKey olur

<----Encrypted {room key} with tempKey--



EL sikisma tamamlandiktan sonra kullanicilar odalara baglanmis olur ve konusmaya baslarlar.
Gonderilen mesajlar serverda toplanir ve room keyler ile sifrelenmis mesajlarin sonuna MAC eklenir.
Koddaki kullandigimiz MAC su sekilde hesaplanmaktadir.

MAC(message) = HMAC(room key concatenate HMAC(room key concatenate,room key),room key)

server MAC hesaplayip dogrularsa bu mesaji kaynak clientin bulundugu odadakilere dagitir.
roomdaki kullanicilar MAC degerini dogrularlarsa mesaji room keyler ile decrypt ederek okurlar.

