#include <eosio/eosio.hpp>
#include <eosio/crypto.hpp>



 
using namespace std;
using namespace eosio;
class [[eosio::contract]] spdz : public eosio::contract {

  private:

    

    struct [[eosio::table]] user_info {
      name            username;
      uint64_t        id;
      string          ip_address;
      uint16_t        port;
      vector<uint64_t>	computation;
      

      auto primary_key() const { return username.value; }
    };

    typedef eosio::multi_index<name("users"), user_info> users_table;

    users_table _users;


     enum computation_status: int8_t  {
      BEGIN   = 1,
      ON_RUNNING   = 2,
      END  = 3
    };


    struct [[eosio::table]]  computation_info {
		    uint64_t    	    id;
        name              initializer;
        string            title;
        string            description;
        string            house_id;
        string            house_descri;
        uint64_t    	    nbplayers;
        uint64_t          min_price;
        uint64_t          winner_id;
        uint64_t          winner_price;
        int8_t            state = BEGIN;
        int8_t            malicious_activity= 1;
        vector<name>	users;
        map<uint64_t, checksum256> commitment1;
        map<uint64_t, int64_t> reveal_commitment1_value;
        map<uint64_t, int64_t> reveal_commitment1_random_value;
        map<uint64_t, checksum256> commitment2;
        map<uint64_t, int64_t> reveal_commitment2_value;
        map<uint64_t, int64_t> reveal_commitment2_random_value;
		    auto primary_key() const { return id; };
		};

    typedef eosio::multi_index<name("computations"),computation_info> computations_table;

    computations_table _computations;

    struct [[eosio::table]] bank_info {
      name            bankname;
      vector<uint64_t>	computation;
      

      auto primary_key() const { return bankname.value; }
    };

    typedef eosio::multi_index<name("banks"),bank_info> banks_table;

    banks_table _banks;


     auto find_user_by_id(name username){
       auto iterator = _users.find(username.value);
        eosio::check(iterator != _users.end(), "user not exist");
        return iterator;
     }

     auto find_bank_by_id(name bankname){
       auto iterator = _banks.find(bankname.value);
        eosio::check(iterator != _banks.end(), "bank not exist");
        return iterator;
     }

     auto verify_user_existance(name username){
      auto user_iterator = _users.find(username.value);
      eosio::check(user_iterator == _users.end(),"user already exist");
      return user_iterator;
     }

     auto verify_bank_existance(name bankname){
      auto bank_iterator = _banks.find(bankname.value);
      eosio::check(bank_iterator == _banks.end(),"bank already exist");
      return bank_iterator;
     }

     auto find_computation_by_id(uint64_t id){
      auto computation_iterator = _computations.find(id);
      eosio::check(computation_iterator != _computations.end(), "computation not exist");
      return computation_iterator;
     }

     void verify_already_added_user(name username,uint64_t compu_id){
        //print(eosioitr->property)  reference
        //print((*itr).property)  instance
        auto computation_iterator=find_computation_by_id(compu_id);
        bool result=false;
        vector<name>::const_iterator itv;
        itv = computation_iterator->users.begin();
        while ((itv != computation_iterator->users.end()) and (!result) ){
          if(*itv==username){
            result=true;
          }
	        else{
	          itv++; 
	        }
        }
        eosio::check(result ==false , "user alreay added.");
     }

     void verify_is_the_user_added(name username,uint64_t compu_id){
      auto computation_iterator=find_computation_by_id(compu_id);
      bool result=false;
      vector<name>::const_iterator itv;
      itv = computation_iterator->users.begin();
      while ((itv != computation_iterator->users.end()) and (!result) ){
        if(*itv==username){
          result=true;
        }
	      else{
	        itv++; 
	      }
      }
      eosio::check(result ==true , "user not added to the computation");
     }


  public:

    spdz( name receiver, name code, datastream<const char*> ds ):contract(receiver, code, ds),
                       _users(receiver, receiver.value),
                       _computations(receiver, receiver.value),
                       _banks(receiver, receiver.value) {}

    //actions
    [[eosio::action]]
    void adduser(name username,string ip_address,uint16_t port){
       // Ensure this action is authorized by the player
      require_auth(username);
      // Create a record in the table if the player doesn't exist in our app yet
      auto user_iterator = verify_user_existance(username);
        user_iterator = _users.emplace(username,  [&](auto& new_user) {
          new_user.username = username;
          new_user.ip_address=ip_address;
          new_user.port=port;
          new_user.id=username.value;
        });
    }

    [[eosio::action]]
    void updateuser(name username,string ip_address,uint16_t port) {
    require_auth(username);
    auto iterator=find_user_by_id(username);
    _users.modify(iterator,username, [&](auto& user) {
        user.ip_address=ip_address;
        user.port=port;
        
    });
    }

    //action
    [[eosio::action]]
    void deleteuser(name username) {
      require_auth(username);
      auto iterator=find_user_by_id(username);
      _users.erase(iterator);
    }

    [[eosio::action]]
    void addbank(name bankname){
       // Ensure this action is authorized by the player
      require_auth(bankname);
      // Create a record in the table if the player doesn't exist in our app yet
      auto bank_iterator = verify_bank_existance(bankname);
        bank_iterator = _banks.emplace(bankname,  [&](auto& new_bank) {
          new_bank.bankname = bankname;
        });
    }


    //action
    [[eosio::action]]
    void addcompu(name bankname,string house_id,string house_descri,string title,string description,uint64_t min_price){
      require_auth(bankname);
      auto bank_iterator=find_bank_by_id(bankname);
      auto computation_iterator = _computations.emplace(bankname,  [&](auto& new_computation) {
          new_computation.id=_computations.available_primary_key();
          new_computation.initializer = bankname;
          new_computation.description=description;
          new_computation.title=title;
          new_computation.nbplayers=0;
          new_computation.min_price=min_price;
          new_computation.house_id=house_id;
          new_computation.house_descri=house_descri;
        });

       _banks.modify(bank_iterator,bankname, [&](auto& bank) {
        bank.computation.push_back(computation_iterator->id);
    });

    }

    //action
    [[eosio::action]]
    void updatecompu(name bankname,string house_id,string house_descri,string title,string description,uint64_t min_price,uint64_t compu_id){
      require_auth(bankname);
      auto computation_iterator =find_computation_by_id(compu_id);
      eosio::check(computation_iterator->initializer==bankname, "Only who create the computation can modify those information");
      eosio::check(computation_iterator->state==1, "Only before running computation, you can modifiy state");
      _computations.modify(computation_iterator,bankname, [&](auto& computation) {
        computation.title=title;
        computation.description=description;
        computation.house_id=house_id;
        computation.house_descri=house_descri;
        computation.min_price=min_price;
    });
    }

    [[eosio::action]]
    void updcompust(name bankname,uint64_t state,uint64_t compu_id){
      require_auth(bankname);
      auto computation_iterator =find_computation_by_id(compu_id);
      eosio::check(computation_iterator->initializer==bankname, "Only who create the computation can modify state");
      if(state==3){
        _computations.modify(computation_iterator,bankname, [&](auto& computation) {
          computation.state=state;
        });
      }else{
        eosio::check(computation_iterator->state==1, "Only before running computation, you can modifiy state");
        _computations.modify(computation_iterator,bankname, [&](auto& computation) {
          computation.state=state;
        });
      }
    }

    //action
    [[eosio::action]]
    void addusercompu(name username,uint64_t compu_id){
      require_auth(username);
      auto user_iterator=find_user_by_id(username);
      auto computation_iterator =find_computation_by_id(compu_id);
      verify_already_added_user(username,compu_id);
      eosio::check(computation_iterator->state==1, "Only before running computation, you can join computation");
      _computations.modify(computation_iterator,username, [&](auto& computation) {
        computation.nbplayers++;
        computation.users.push_back(username);
      });

       _users.modify(user_iterator,username, [&](auto& user) {
        user.computation.push_back(computation_iterator->id);
    });

    }


    [[eosio::action]]
    void winner(name username,uint64_t compu_id,uint64_t winner_id,uint64_t price) {
      require_auth(username);
      auto iterator=find_user_by_id(username);
      auto computation_iterator=find_computation_by_id(compu_id);
      verify_is_the_user_added(username,compu_id);

        _computations.modify(computation_iterator,username, [&](auto& computation) {
          computation.winner_id=winner_id;
          computation.winner_price=price;
        });


  }

   [[eosio::action]]
    void addcommit(name username,uint64_t compu_id,const eosio::checksum256 &commitment,uint64_t phase) {
      require_auth(username);
      auto iterator=find_user_by_id(username);
      auto computation_iterator=find_computation_by_id(compu_id);
      verify_is_the_user_added(username,compu_id);

      if(phase==1){
        _computations.modify(computation_iterator,username, [&](auto& computation) {
          computation.commitment1.insert(std::make_pair(username.value,commitment));
        });
      }else if(phase==2){
         _computations.modify(computation_iterator,username, [&](auto& computation) {
          computation.commitment2.insert(std::make_pair(username.value,commitment));
        });
      }

  }


    [[eosio::action]]
    void reveal(name username,uint64_t compu_id,const string &value,const string &random_value,uint64_t phase) {
      require_auth(username);
      auto iterator=find_user_by_id(username);
      auto computation_iterator=find_computation_by_id(compu_id);
      verify_is_the_user_added(username,compu_id);
      
      if(phase==1){
        _computations.modify(computation_iterator,username, [&](auto& computation) {
          computation.reveal_commitment1_value.insert(std::make_pair(username.value, std::stoi(value)));
          computation.reveal_commitment1_random_value.insert(std::make_pair(username.value, std::stoi(random_value)));
        });
        /*if(computation_iterator->reveal_commitment1_value.size()==computation_iterator->nbplayers){
          eosio::transaction t{};
          t.actions.emplace_back(
            // when sending to _self a different authorization can be used
            // otherwise _self must be used
            permission_level(username, "active"_n),
            // account the action should be send to
            _self,
            // action to invoke
            "checkcompuoff"_n,
            // arguments for the action
            std::make_tuple(username,compu_id ));
          // set delay in seconds
          t.delay_sec = 0;
          t.send(now(),username);
        }*/
      }else if(phase==2){
        _computations.modify(computation_iterator,username, [&](auto& computation) {
          computation.reveal_commitment2_value.insert(std::make_pair(username.value, std::stoi(value)));
          computation.reveal_commitment2_random_value.insert(std::make_pair(username.value, std::stoi(random_value)));
        });
      }
      

      // checks if sha256(p1_rand_as_hex, bytes_size) == third argument
      //the important ligne of code of this function
      //eosio::assert_sha256((char *)p1_rand_as_hex.c_str(),p1_rand_as_hex.size(),computation_iterator->commitment1.find(username.value)->second);
  }

    [[eosio::action]]
    void checkcompu(name bankname,uint64_t compu_id){
      require_auth(bankname);
      auto iterator=find_bank_by_id(bankname);
      auto computation_iterator=find_computation_by_id(compu_id);
      //verify_is_the_user_added(username,compu_id);
      eosio::check(computation_iterator->initializer==bankname, "Only who create the computation can modify state");
      eosio::check(computation_iterator->malicious_activity==1, "computation already verified");

    if(computation_iterator->reveal_commitment1_value.size()==computation_iterator->nbplayers){
            if(computation_iterator->users.size()==2){
            auto it_value = computation_iterator->reveal_commitment1_value.begin();
            uint64_t sum=0;
            while (it_value != computation_iterator->reveal_commitment1_value.end())
	          {
		          // Accessing KEY from element.
              uint64_t key= it_value->first;
		          // Accessing VALUE from element.
		          int64_t value = it_value->second;
              // Accessing random from element.
              int64_t random=computation_iterator->reveal_commitment1_random_value.find(key)->second;
              std::string value_str = std::to_string(value);
              std::string random_str = std::to_string(random);
              std::string all_value=random_str+value_str;
              eosio::assert_sha256((char *)all_value.c_str(),all_value.size(),computation_iterator->commitment1.find(key)->second);
		          sum=sum+value;
              print("sum is : ",sum);
              // Increment the Iterator to point to next entry
		          it_value++;
	          }
            print("sum is : ",sum);
            eosio::check(sum==0, "malicious activity on the offline phase");
            _computations.modify(computation_iterator,bankname, [&](auto& computation) {
              computation.malicious_activity=0;
            });
            }
        
      if(computation_iterator->users.size()==3){
            uint64_t sum=0;
            auto it_value = computation_iterator->reveal_commitment2_value.begin();
            while (it_value != computation_iterator->reveal_commitment2_value.end())
	          {
		          // Accessing KEY from element.
              uint64_t key= it_value->first;
		          // Accessing VALUE from element.
		          int64_t value = it_value->second;
              // Accessing random from element.
              int64_t random=computation_iterator->reveal_commitment2_random_value.find(key)->second;
              std::string value_str = std::to_string(value);
              std::string random_str = std::to_string(random);
              std::string all_value=random_str+value_str;
              print(all_value);
              eosio::assert_sha256((char *)all_value.c_str(),all_value.size(),computation_iterator->commitment2.find(key)->second);
		          sum=sum+value;
              // Increment the Iterator to point to next entry
		          it_value++;
	          }
            eosio::check(sum==0, "malicious activity on the online phase");
            _computations.modify(computation_iterator,bankname, [&](auto& computation) {
              computation.malicious_activity=0;
            });
            
        

      }
    }
    }



   /* [[eosio::action]]
    void checkcompuon(name username,uint64_t compu_id){
      require_auth(username);
      auto iterator=find_user_by_id(username);
      auto computation_iterator=find_computation_by_id(compu_id);
      verify_is_the_user_added(username,compu_id);
      eosio::check(computation_iterator->malicious_activity2==1, "computation already verified");

    if(computation_iterator->reveal_commitment2_value.size()==computation_iterator->nbplayers){
            uint64_t sum=0;
            auto it_value = computation_iterator->reveal_commitment2_value.begin();
            while (it_value != computation_iterator->reveal_commitment2_value.end())
	          {
		          // Accessing KEY from element.
              uint64_t key= it_value->first;
		          // Accessing VALUE from element.
		          int64_t value = it_value->second;
              // Accessing random from element.
              int64_t random=computation_iterator->reveal_commitment2_random_value.find(key)->second;
              std::string value_str = std::to_string(value);
              std::string random_str = std::to_string(random);
              std::string all_value=random_str+value_str;
              print(all_value);
              eosio::assert_sha256((char *)all_value.c_str(),all_value.size(),computation_iterator->commitment2.find(key)->second);
		          sum=sum+value;
              // Increment the Iterator to point to next entry
		          it_value++;
	          }
            eosio::check(sum==0, "malicious activity on the online phase");
            _computations.modify(computation_iterator,username, [&](auto& computation) {
              computation.malicious_activity2=0;
            });
            
        }
    }*/


};
