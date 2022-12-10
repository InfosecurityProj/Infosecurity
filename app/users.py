class User:
    count_id = 0

    def __init__(self, first_name, last_name, gender, title, emails, password, confirm_password, type, salt):
        User.count_id += 1
        self.__user_id = User.count_id
        self.__first_name = first_name
        self.__last_name = last_name
        self.__gender = gender
        self.__title = title
        self.__emails = emails
        self.__password = password
        self.__confirm_password = confirm_password
        self.__type = type
        self.__salt = salt

    def get_user_id(self):
        return self.__user_id

    def get_first_name(self):
        return self.__first_name

    def get_last_name(self):
        return self.__last_name

    def get_gender(self):
        return self.__gender

    def get_title(self):
        return self.__title

    def get_emails(self):
        return self.__emails

    def get_password(self):
        return self.__password

    def get_confirm_password(self):
        return self.__confirm_password

    def get_type(self):
        return self.__type

    def get_salt(self):
        return self.__salt

    def set_user_id(self, user_id):
        self.__user_id = user_id

    def set_first_name(self, first_name):
        self.__first_name = first_name

    def set_last_name(self, last_name):
        self.__last_name = last_name

    def set_gender(self, gender):
        self.__gender = gender

    def set_title(self, title):
        self.__title = title

    def set_emails(self, emails):
        self.__emails = emails

    def set_password(self, password):
        self.__password = password

    def set_confirm_password(self, confirm_password):
        self.__confirm_password = confirm_password

    def set_type(self, type):
        self.__type = type

    def set_salt(self, salt):
        self.__salt = salt
