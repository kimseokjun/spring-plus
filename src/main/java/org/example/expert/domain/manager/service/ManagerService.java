package org.example.expert.domain.manager.service;

import lombok.RequiredArgsConstructor;
import org.example.expert.domain.common.dto.AuthUser;
import org.example.expert.domain.common.exception.InvalidRequestException;
import org.example.expert.domain.log.service.LogService;
import org.example.expert.domain.manager.dto.request.ManagerSaveRequest;
import org.example.expert.domain.manager.dto.response.ManagerResponse;
import org.example.expert.domain.manager.dto.response.ManagerSaveResponse;
import org.example.expert.domain.manager.entity.Manager;
import org.example.expert.domain.manager.repository.ManagerRepository;
import org.example.expert.domain.todo.entity.Todo;
import org.example.expert.domain.todo.repository.TodoRepository;
import org.example.expert.domain.user.dto.response.UserResponse;
import org.example.expert.domain.user.entity.User;
import org.example.expert.domain.user.repository.UserRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.ObjectUtils;

import java.util.ArrayList;
import java.util.List;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class ManagerService {

    private final ManagerRepository managerRepository;
    private final UserRepository userRepository;
    private final TodoRepository todoRepository;
    private final LogService logService;

    @Transactional
    public ManagerSaveResponse saveManager(AuthUser authUser, long todoId, ManagerSaveRequest managerSaveRequest) {
        // 일정을 만든 유저
        User user = User.fromAuthUser(authUser);

        try {
            Todo todo = todoRepository.findById(todoId)
                    .orElseThrow(() -> new InvalidRequestException("Todo not found"));

            if (todo.getUser() == null || !ObjectUtils.nullSafeEquals(user.getId(), todo.getUser().getId())) {
                throw new InvalidRequestException("담당자를 등록하려고 하는 유저가 유효하지 않거나, 일정을 만든 유저가 아닙니다.");
            }

            User managerUser = userRepository.findById(managerSaveRequest.getManagerUserId())
                    .orElseThrow(() -> new InvalidRequestException("등록하려고 하는 담당자 유저가 존재하지 않습니다."));

            if (ObjectUtils.nullSafeEquals(user.getId(), managerUser.getId())) {
                throw new InvalidRequestException("일정 작성자는 본인을 담당자로 등록할 수 없습니다.");
            }

            logService.saveLog("MANAGER_SAVE", "성공");
            Manager newManagerUser = new Manager(managerUser, todo);
            Manager savedManagerUser = managerRepository.save(newManagerUser);

            return new ManagerSaveResponse(
                    savedManagerUser.getId(),
                    new UserResponse(managerUser.getId(), managerUser.getEmail())
            );
        } catch (Exception ex) {
            System.out.println("실패실패");
            logService.saveLog("MANAGER_SAVE", "실패");
            throw ex;
        }

    }

    public List<ManagerResponse> getManagers(long todoId) {
        Todo todo = todoRepository.findById(todoId)
                .orElseThrow(() -> new InvalidRequestException("Todo not found"));

        List<Manager> managerList = managerRepository.findByTodoIdWithUser(todo.getId());

        List<ManagerResponse> dtoList = new ArrayList<>();
        for (Manager manager : managerList) {
            User user = manager.getUser();
            dtoList.add(new ManagerResponse(
                    manager.getId(),
                    new UserResponse(user.getId(), user.getEmail())
            ));
        }
        return dtoList;
    }

    @Transactional
    public void deleteManager(AuthUser authUser, long todoId, long managerId) {
        User user = User.fromAuthUser(authUser);

        Todo todo = todoRepository.findById(todoId)
                .orElseThrow(() -> new InvalidRequestException("Todo not found"));

        if (todo.getUser() == null || !ObjectUtils.nullSafeEquals(user.getId(), todo.getUser().getId())) {
            throw new InvalidRequestException("해당 일정을 만든 유저가 유효하지 않습니다.");
        }

        Manager manager = managerRepository.findById(managerId)
                .orElseThrow(() -> new InvalidRequestException("Manager not found"));

        if (!ObjectUtils.nullSafeEquals(todo.getId(), manager.getTodo().getId())) {
            throw new InvalidRequestException("해당 일정에 등록된 담당자가 아닙니다.");
        }

        managerRepository.delete(manager);
    }
}
