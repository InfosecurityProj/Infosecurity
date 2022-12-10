class Reservation:
    count_id = 0

    def __init__(self, name, email, number, date, time, party_size):
        Reservation.count_id += 1
        self.__user_id = Reservation.count_id
        self.__name = name
        self.__email = email
        self.__number = number
        self.__date = date
        self.__time = time
        self.__party_size = party_size

    def get_user_id(self):
        return self.__user_id

    def get_name(self):
        return self.__name

    def get_email(self):
        return self.__email

    def get_number(self):
        return self.__number

    def get_date(self):
        return self.__date

    def get_time(self):
        return self.__time

    def get_party_size(self):
        return self.__party_size

    def set_user_id(self, user_id):
        self.__user_id = user_id

    def set_name(self, name):
        self.__name = name

    def set_email(self, email):
        self.__email = email

    def set_number(self, number):
        self.__number = number

    def set_date(self, date):
        self.__date = date

    def set_time(self, time):
        self.__time = time

    def set_party_size(self, party_size):
        self.__party_size = party_size