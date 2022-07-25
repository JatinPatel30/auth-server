package com.jp.auth.authserver.repository;

import com.jp.auth.authserver.repository.model.Users;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UsersRepository extends MongoRepository<Users, String> {
    Users findByUsername(String username);
}
