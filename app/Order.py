class Order:
    count_id = 0

    def __init__(self, order_item, meat, sauce, remarks, price, email):
        Order.count_id += 1
        self.__order_id = Order.count_id
        self.__order_item = order_item
        self.__meat = meat
        self.__sauce = sauce
        self.__remarks = remarks
        self.__price = price
        self.__email = email

    def get_order_id(self):
        return self.__order_id

    def get_order_item(self):
        return self.__order_item

    def get_meat(self):
        return self.__meat

    def get_sauce(self):
        return self.__sauce

    def get_remarks(self):
        return self.__remarks

    def get_price(self):
        return self.__price

    def get_email(self):
        return self.__email

    def set_order_id(self, order_id):
        self.__order_id = order_id

    def set_order_item(self, order_item):
        self.__order_item = order_item

    def set_meat(self, meat):
        self.__meat = meat

    def set_sauce(self, sauce):
        self.__sauce = sauce

    def set_remarks(self, remarks):
        self.__remarks = remarks

    def set_price(self, price):
        self.__price = price

    def set_email(self, email):
        self.__email = email