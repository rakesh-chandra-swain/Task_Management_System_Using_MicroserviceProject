package com.nt.model;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import com.nt.domains.TaskStatus;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class TaskDto {

	 private Long id;
	 private String title;
	 private String description;
	 private String image;
	 private Long assigendUserId;
	 private List<String> tags=new ArrayList<>();
	 private TaskStatus status;
	 private LocalDateTime deadline;
	 private LocalDateTime createdAt;

}
